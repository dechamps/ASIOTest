#include "test.h"

#include <algorithm>
#include <condition_variable>
#include <chrono>
#include <iostream>
#include <functional>
#include <mutex>
#include <optional>
#include <string_view>
#include <thread>
#include <vector>
#include <cstdlib>
#include <sstream>
#include <variant>

#include <sndfile.h>

#include <dechamps_ASIOUtil/asiosdk/ginclude.h>
#include <dechamps_ASIOUtil/asiosdk/asio.h>
#include <dechamps_ASIOUtil/asio.h>

#pragma warning(push)
#pragma warning(disable:4018 4267)
#include <cxxopts.hpp>
#pragma warning(pop)

#include <dechamps_cpputil/endian.h>
#include <dechamps_cpputil/find.h>
#include <dechamps_cpputil/string.h>

#include <dechamps_cpplog/log.h>

#include <windows.h>

// The global ASIO driver pointer that the ASIO host library internally uses.
extern IASIO* theAsioDriver;

namespace ASIOTest {
	namespace {

		std::vector<long> getChannelIndices(const std::string& str)
		{
			if (str == "none") return {};

			std::istringstream stream(str);
			std::vector<long> channelIndices;
			for (;;) {
				stream >> channelIndices.emplace_back();
				if (stream.fail()) throw std::runtime_error("invalid channel index list");
				if (stream.peek() == decltype(stream)::traits_type::eof()) break;
				if (stream.peek() != ',') throw std::runtime_error(std::string("invalid channel index list: unexpected character '") + char(stream.peek()) + "'");
				stream.get();
			}
			return channelIndices;
		}

		enum class LogMode { NONE, SYNC, ASYNC };

		struct Config {
			// Run enough buffer switches such that we can trigger failure modes like https://github.com/dechamps/FlexASIO/issues/29.
			static constexpr size_t defaultBufferSwitchCount = 30;

			bool openControlPanel = false;
			std::optional<long> bufferSizeFrames;
			std::optional<size_t> bufferSwitchCount;
			double bufferSwitchDelayMs = 0;
			bool inhibitOutputReady;
			std::optional<std::vector<long>> inputChannels;
			std::optional<std::vector<long>> outputChannels;
			std::optional<std::string> playbackFromFile;
			LogMode logMode;
			bool verboseLog = false;
			std::optional<std::string> recordToFile;
			std::optional<double> sampleRate;
		};

		std::optional<Config> GetConfig(int& argc, char**& argv) {
			cxxopts::Options options("ASIOTest", "ASIO driver test program");
			Config config;
			std::optional<std::string> inputChannels;
			std::optional<std::string> outputChannels;
			std::string logMode = "async";
			options.add_options()
				("open-control-panel", "Open the ASIO Control Panel, then exit", cxxopts::value(config.openControlPanel))
				("buffer-size-frames", "ASIO buffer size to use, in frames; default is to use the preferred size suggested by the driver", cxxopts::value(config.bufferSizeFrames))
				("buffer-switch-count", "Stop after this many ASIO buffers have been switched; default is to stop when reaching the end of the input file, if any; otherwise, " + std::to_string(config.defaultBufferSwitchCount), cxxopts::value(config.bufferSwitchCount))
				("buffer-switch-delay-ms", "Sleep for this many milliseconds before processing a buffer switch callback; default is " + std::to_string(config.bufferSwitchDelayMs), cxxopts::value(config.bufferSwitchDelayMs))
				("inhibit-output-ready", "Don't call ASIOOutputReady() to inform the driver when the output buffer has been filled.", cxxopts::value(config.inhibitOutputReady))
				("input-channels", "Comma-separated list of input channel indices (zero-based) to enable; pass \"none\" to disable all input channels; default is to enable all input channels", cxxopts::value(inputChannels))
				("output-channels", "Comma-separated list of output channel indices (zero-based) to enable; pass \"none\" to disable all output channels; default is to enable all output channels", cxxopts::value(outputChannels))
				("playback-from-file", "Preload the specified audio file, then play the untouched raw audio buffers to the ASIO driver.", cxxopts::value(config.playbackFromFile))
				("verbose", "Output a more detailed and more technical log", cxxopts::value(config.verboseLog))
				("log-mode", "How to output the log; can be 'none' (do not output the log, maximum performance), 'sync' (output the log synchronously, useful for debugging crashes) or 'async' (output the log asynchronously, useful to prevent slow output from affecting real time operation); default is '" + logMode + "'", cxxopts::value(logMode))
				("record-to-file", "Record untouched raw audio buffers from the ASIO driver, then write them to the specified file; output format is WAV for little-endian sample types (ASIOST*LSB), AIFF for big-endian sample types (ASIOST*MSB).", cxxopts::value(config.recordToFile))
				("sample-rate", "ASIO sample rate to use; default is to use the input file sample rate, if any, otherwise the initial sample rate of the driver", cxxopts::value(config.sampleRate));
			try {
				options.parse(argc, argv);

				if (inputChannels.has_value()) {
					config.inputChannels = getChannelIndices(*inputChannels);
					if (config.inputChannels->empty() && config.recordToFile.has_value()) throw std::runtime_error("Must specify at least one input channel when recording to a file");
				}
				if (outputChannels.has_value()) {
					config.outputChannels = getChannelIndices(*outputChannels);
					if (config.outputChannels->empty() && config.playbackFromFile.has_value()) throw std::runtime_error("Must specify at least one output channel when playing back from a file");
				}

				if (logMode == "none") config.logMode = LogMode::NONE;
				else if (logMode == "sync") config.logMode = LogMode::SYNC;
				else if (logMode == "async") config.logMode = LogMode::ASYNC;
				else throw std::runtime_error("Invalid --log-mode setting");
			}
			catch (const std::exception& exception) {
				std::cerr << "USAGE ERROR: " << exception.what() << std::endl;
				std::cerr << std::endl;
				std::cerr << options.help() << std::endl;
				return std::nullopt;
			}
			return config;
		}

		struct LogState final {
		public:
			LogState(bool verbose, LogMode mode) : verbose(verbose) {
				switch (mode) {
				case LogMode::NONE:
					sink.emplace<None>();
					break;
				case LogMode::ASYNC:
					sink.emplace<AsyncStdout>(verbose);
					break;
				case LogMode::SYNC:
					sink.emplace<SyncStdout>(verbose);
					break;
				}
			}

			bool isVerbose() const { return verbose;  }
			::dechamps_cpplog::LogSink* getSink() {
				return std::visit([](auto& sink) { return sink.sink(); }, sink);
			}

		private:
			class None final {
			public:
				::dechamps_cpplog::LogSink* sink() { return nullptr; }
			};

			template <typename IntermediateLogSink>
			class Stdout final {
			public:
				explicit Stdout(bool verbose) {
					if (verbose) preamble_sink.emplace(intermediate_sink);
				}

				::dechamps_cpplog::LogSink* sink() {
					if (preamble_sink) return &*preamble_sink;
					return &intermediate_sink;
				}

			private:
				::dechamps_cpplog::StreamLogSink stream_sink{ std::cout };
				IntermediateLogSink intermediate_sink{ stream_sink };
				std::optional<::dechamps_cpplog::PreambleLogSink> preamble_sink;
			};
			
			using SyncStdout = Stdout<::dechamps_cpplog::ThreadSafeLogSink>;
			using AsyncStdout = Stdout<::dechamps_cpplog::AsyncLogSink>;

			const bool verbose;
			std::variant<None, SyncStdout, AsyncStdout> sink;
		};
		static std::optional<LogState> logState;

		::dechamps_cpplog::Logger Log(bool verbose = true) {
			if (!logState.has_value()) abort();
			if (verbose && !logState->isVerbose()) return ::dechamps_cpplog::Logger(nullptr);
			::dechamps_cpplog::Logger::Options loggerOptions;
			loggerOptions.prependTime = loggerOptions.prependProcessId = loggerOptions.prependThreadId = logState->isVerbose();
			return ::dechamps_cpplog::Logger(logState->getSink(), loggerOptions);
		}

		std::vector<long> PopulateChannels(const std::optional<std::vector<long>>& configuredChannels, const long availableChannelCount, const std::string_view label) {
			std::vector<long> channels;
			if (configuredChannels.has_value()) channels = *configuredChannels;
			else for (long channel = 0; channel < availableChannelCount; ++channel) channels.push_back(channel);

			for (const auto& channel : channels) {
				if (channel < 0 || channel >= availableChannelCount)
					throw std::runtime_error(std::string(label) + " channel " + std::to_string(channel) + " is out of range (" + std::to_string(availableChannelCount) + " channels available)");
			}

			return channels;
		};

		class ConsoleCtrlHandler {
		public:
			ConsoleCtrlHandler(std::function<BOOL(DWORD)> handler) : handler(std::move(handler)) {
				if (global != nullptr) abort();
				global = this;
				SetConsoleCtrlHandler(Handle, /*Add=*/TRUE);
			}
			~ConsoleCtrlHandler() {
				if (global != this) abort();
				SetConsoleCtrlHandler(Handle, /*Add=*/FALSE);
				global = nullptr;
			}

		private:
			static BOOL WINAPI Handle(DWORD dwCtrlType) {
				if (global == nullptr) abort();
				return global->handler(dwCtrlType);
			}

			static ConsoleCtrlHandler* global;
			std::function<BOOL(DWORD)> handler;
		};
		ConsoleCtrlHandler* ConsoleCtrlHandler::global = nullptr;

		ASIOSampleType GetCommonSampleType(const std::vector<ASIOChannelInfo>& channelInfos, const bool input) {
			std::optional<ASIOSampleType> sampleType;
			for (const auto& channelInfo : channelInfos) {
				if (!!channelInfo.isInput != input) continue;
				if (!sampleType.has_value()) {
					sampleType = channelInfo.type;
					continue;
				}
				if (*sampleType != channelInfo.type) throw std::runtime_error(std::string(input ? "Input" : "Output") + " channels don't have the same sample type (found " + ::dechamps_ASIOUtil::GetASIOSampleTypeString(*sampleType) + " and " + ::dechamps_ASIOUtil::GetASIOSampleTypeString(channelInfo.type));
			}
			if (!sampleType.has_value()) throw std::runtime_error(std::string("No ") + (input ? "input" : "output") + " channels");
			return *sampleType;
		}

		std::optional<int> ASIOSampleTypeToSfFormatType(const ASIOSampleType sampleType) {
			return ::dechamps_cpputil::Find(sampleType, std::initializer_list<std::pair<ASIOSampleType, int>>{
				{ASIOSTInt16MSB, SF_FORMAT_PCM_16 | SF_ENDIAN_BIG},
				{ ASIOSTInt24MSB, SF_FORMAT_PCM_24 | SF_ENDIAN_BIG },
				{ ASIOSTInt32MSB, SF_FORMAT_PCM_32 | SF_ENDIAN_BIG },
				{ ASIOSTFloat32MSB, SF_FORMAT_FLOAT | SF_ENDIAN_BIG },
				{ ASIOSTFloat64MSB, SF_FORMAT_DOUBLE | SF_ENDIAN_BIG },
				{ ASIOSTInt16LSB, SF_FORMAT_PCM_16 | SF_ENDIAN_LITTLE },
				{ ASIOSTInt24LSB, SF_FORMAT_PCM_24 | SF_ENDIAN_LITTLE },
				{ ASIOSTInt32LSB, SF_FORMAT_PCM_32 | SF_ENDIAN_LITTLE },
				{ ASIOSTFloat32LSB, SF_FORMAT_FLOAT | SF_ENDIAN_LITTLE },
				{ ASIOSTFloat64LSB, SF_FORMAT_DOUBLE | SF_ENDIAN_LITTLE },
			});
		}
		std::optional<ASIOSampleType> SfFormatToASIOSampleType(const int sfFormat, ::dechamps_cpputil::Endianness fileEndianness) {
			return ::dechamps_cpputil::Find(sfFormat & SF_FORMAT_SUBMASK, std::initializer_list<std::pair<int, ASIOSampleType>>{
				{ SF_FORMAT_PCM_16, fileEndianness == ::dechamps_cpputil::Endianness::BIG ? ASIOSTInt16MSB : ASIOSTInt16LSB },
				{ SF_FORMAT_PCM_24, fileEndianness == ::dechamps_cpputil::Endianness::BIG ? ASIOSTInt24MSB : ASIOSTInt24LSB },
				{ SF_FORMAT_PCM_32, fileEndianness == ::dechamps_cpputil::Endianness::BIG ? ASIOSTInt32MSB : ASIOSTInt32LSB },
				{ SF_FORMAT_FLOAT, fileEndianness == ::dechamps_cpputil::Endianness::BIG ? ASIOSTFloat32MSB : ASIOSTFloat32LSB },
				{ SF_FORMAT_DOUBLE, fileEndianness == ::dechamps_cpputil::Endianness::BIG ? ASIOSTFloat64MSB : ASIOSTFloat64LSB },
			});
		}

		void CopyToInterleavedBuffer(const std::vector<ASIOBufferInfo>& bufferInfos, const size_t sampleSize, const size_t bufferSizeInSamples, const long doubleBufferIndex, void* const interleavedBuffer, const size_t interleavedBufferChannelCount) {
			size_t channelOffset = 0;
			for (const auto& bufferInfo : bufferInfos) {
				if (!bufferInfo.isInput) continue;

				if (channelOffset >= interleavedBufferChannelCount) abort();
				const auto buffer = static_cast<uint8_t*>(bufferInfo.buffers[doubleBufferIndex]);

				for (size_t sampleCount = 0; sampleCount < bufferSizeInSamples; ++sampleCount)
					memcpy(static_cast<uint8_t*>(interleavedBuffer) + (interleavedBufferChannelCount * sampleCount + channelOffset) * sampleSize, buffer + sampleCount * sampleSize, sampleSize);

				++channelOffset;
			}
		}

		void CopyFromInterleavedBuffer(const std::vector<ASIOBufferInfo>& bufferInfos, const size_t sampleSize, const size_t bufferSizeInSamples, const long doubleBufferIndex, const void* const interleavedBuffer, const size_t interleavedBufferChannelCount) {
			size_t channelOffset = 0;
			for (const auto& bufferInfo : bufferInfos) {
				if (bufferInfo.isInput) continue;

				if (channelOffset >= interleavedBufferChannelCount) abort();
				const auto buffer = static_cast<uint8_t*>(bufferInfo.buffers[doubleBufferIndex]);

				for (size_t sampleCount = 0; sampleCount < bufferSizeInSamples; ++sampleCount)
					memcpy(buffer + sampleCount * sampleSize, static_cast<const uint8_t*>(interleavedBuffer) + (interleavedBufferChannelCount * sampleCount + channelOffset) * sampleSize, sampleSize);

				++channelOffset;
			}
		}

		struct SndfileCloser final {
			void operator()(SNDFILE* const sndfile) {
				const auto closeError = sf_close(sndfile);
				if (closeError != 0) std::cerr << "Error while closing output file: " << sf_error_number(closeError) << std::endl;
			}
		};
		using SndfileUniquePtr = std::unique_ptr<SNDFILE, SndfileCloser>;

		using SndfileWithInfo = std::pair<SndfileUniquePtr, SF_INFO>;
		SndfileWithInfo OpenSndfile(const std::string_view path, int mode, SF_INFO sfInfo = { 0 }) {
			SndfileUniquePtr sndfile(sf_open(std::string(path).c_str(), mode, &sfInfo));
			if (sndfile == NULL) throw std::runtime_error("Unable to open sound file '" + std::string(path) + "': " + sf_strerror(NULL));
			return { std::move(sndfile), sfInfo };
		}

		::dechamps_cpputil::Endianness GetSndfileEndianness(SNDFILE* const sndfile) {
			const auto result = sf_command(sndfile, SFC_RAW_DATA_NEEDS_ENDSWAP, NULL, 0);
			if (result == SF_FALSE) return ::dechamps_cpputil::endianness;
			if (result == SF_TRUE) return ::dechamps_cpputil::OppositeEndianness(::dechamps_cpputil::endianness);
			throw std::runtime_error(std::string("Unable to determine endianness of sound file: ") + sf_error_number(result));
		}

		class PlaybackFile {
		public:
			PlaybackFile(const std::string_view path) : sndfile(OpenSndfile(path, SFM_READ)) {}

			int SampleRate() const { return sndfile.second.samplerate; }

			void Validate(const int sampleRate, const int channels, const ASIOSampleType sampleType) const {
				if (sndfile.second.samplerate != sampleRate) throw std::runtime_error("Input file sample rate mismatch: expected " + std::to_string(sampleRate) + ", got " + std::to_string(sndfile.second.samplerate));
				if (sndfile.second.channels != channels) throw std::runtime_error("Input file channel count mismatch: expected " + std::to_string(channels) + ", got " + std::to_string(sndfile.second.channels));
				const auto fileSampleType = SfFormatToASIOSampleType(sndfile.second.format, GetSndfileEndianness(sndfile.first.get()));
				if (!fileSampleType.has_value()) throw std::runtime_error("Unrecognized input file sample type");
				if (*fileSampleType != sampleType) throw std::runtime_error("Input file sample type mismatch: expected " + ::dechamps_ASIOUtil::GetASIOSampleTypeString(sampleType) + ", got " + ::dechamps_ASIOUtil::GetASIOSampleTypeString(*fileSampleType));
			}

			std::vector<uint8_t> Read() {
				const auto readSizeBytes = 12 * sndfile.second.channels * 1024;  // 12 is the least common multiple of 2 (16-bit), 3 (24-bit) and 4 (32-bit), so the read will always be aligned
				std::vector<uint8_t> data;
				for (;;) {
					data.resize(data.size() + readSizeBytes);
					const auto bytesRead = sf_read_raw(sndfile.first.get(), data.data() + data.size() - readSizeBytes, readSizeBytes);
					if (bytesRead <= 0 || bytesRead > readSizeBytes) {
						const auto sfError = sf_error(sndfile.first.get());
						if (bytesRead != 0 || sfError != SF_ERR_NO_ERROR) throw std::runtime_error(std::string("Unable to read input file: ") + sf_error_number(sfError));
					}
					data.resize(data.size() - readSizeBytes + size_t(bytesRead));
					if (bytesRead == 0) break;
				}
				return data;
			}

		private:
			const SndfileWithInfo sndfile;
		};

		class RecordFile {
		public:
			RecordFile(const std::string_view path, const int sampleRate, const int channels, const ASIOSampleType sampleType) :
				sndfile(OpenSndfile(path, SFM_WRITE, GetSfInfo(sampleRate, channels, sampleType))) {}

			void Write(const std::vector<uint8_t>& interleavedBuffer) {
				for (auto bufferIt = interleavedBuffer.begin(); bufferIt < interleavedBuffer.end(); ) {
					const auto bytesToWrite = interleavedBuffer.end() - bufferIt;
					const auto bytesWritten = sf_write_raw(sndfile.first.get(), const_cast<uint8_t*>(&*bufferIt), bytesToWrite);
					if (bytesWritten <= 0 || bytesWritten > bytesToWrite) throw std::runtime_error(std::string("Unable to write to output file: ") + sf_strerror(sndfile.first.get()));
					bufferIt += int(bytesWritten);
				}
			}

		private:
			static SF_INFO GetSfInfo(const int sampleRate, const int channels, const ASIOSampleType sampleType) {
				const auto sfFormat = ASIOSampleTypeToSfFormatType(sampleType);
				if (!sfFormat.has_value()) throw std::runtime_error("ASIO sample type " + ::dechamps_ASIOUtil::GetASIOSampleTypeString(sampleType) + " is not supported as an output file format");

				SF_INFO sfInfo = { 0 };
				sfInfo.samplerate = sampleRate;
				sfInfo.channels = channels;
				switch (*sfFormat & SF_FORMAT_ENDMASK) {
				case SF_ENDIAN_LITTLE: sfInfo.format = SF_FORMAT_WAVEX | *sfFormat; break;
				case SF_ENDIAN_BIG: sfInfo.format = SF_FORMAT_AIFF | *sfFormat; break;
				default: abort();
				}
				return sfInfo;
			}

			const SndfileWithInfo sndfile;
		};

		template <typename FunctionPointer> struct function_pointer_traits;
		template <typename ReturnValue, typename... Args> struct function_pointer_traits<ReturnValue(*)(Args...)> {
			using function = std::function<ReturnValue(Args...)>;
		};

		ASIOError PrintError(ASIOError error) {
			const auto errorString = ::dechamps_ASIOUtil::GetASIOErrorString(error);
			Log(true) << "-> " << errorString;
			if (error != ASE_OK) {
				Log(false) << "Driver returned an error: " << errorString;
			}
			return error;
		}

		using ASIOMessageHandler = decltype(ASIOCallbacks::asioMessage);

		long HandleSelectorSupportedMessage(long, long value, void*, double*);

		long HandleSupportsTimeInfoMessage(long, long, void*, double*) { return 1; }

		constexpr std::pair<long, ASIOMessageHandler> message_selector_handlers[] = {
				{kAsioSelectorSupported, HandleSelectorSupportedMessage},
				{kAsioSupportsTimeInfo, HandleSupportsTimeInfoMessage},
		};

		long HandleSelectorSupportedMessage(long, long value, void*, double*) {
			Log() << "Being queried for message selector " << ::dechamps_ASIOUtil::GetASIOMessageSelectorString(value);
			return ::dechamps_cpputil::Find(value, message_selector_handlers).has_value() ? 1 : 0;
		}

		class ASIOTest {
		public:
			ASIOTest(Config config) : config(std::move(config)) {
				if (logState.has_value()) abort();
				logState.emplace(config.verboseLog, config.logMode);
			}
			~ASIOTest() {
				if (!logState.has_value()) abort();
				logState.reset();
			}

			bool Run() {
				try {
					const bool result = RunInitialized();
					Log(false);
					Log(false) << "Testing finished with " << (result ? "PASS" : "FAIL") << " result";
					return result;
				}
				catch (const std::exception& exception) {
					Log(false) << "FATAL ERROR: " << exception.what();
					return false;
				}
			}

		private:
			std::optional<ASIODriverInfo> Init() {
				ASIODriverInfo asioDriverInfo = { 0 };
				asioDriverInfo.asioVersion = 2;
				Log(false) << "Initializing driver...";
				Log() << "ASIOInit(asioVersion = " << asioDriverInfo.asioVersion << ")";
				const auto initError = PrintError(ASIOInit(&asioDriverInfo));
				Log() << "asioVersion = " << asioDriverInfo.asioVersion << " driverVersion = " << asioDriverInfo.asioVersion << " name = " << asioDriverInfo.name << " errorMessage = " << asioDriverInfo.errorMessage << " sysRef = " << asioDriverInfo.sysRef;
				if (initError != ASE_OK) {
					Log(false) << "...FAILED with error message: " << asioDriverInfo.errorMessage;
					return std::nullopt;
				}
				Log(false) << "...OK, driver name: " << asioDriverInfo.name;
				return asioDriverInfo;
			}

			bool ControlPanel() {
				Log() << "ASIOControlPanel()";
				return PrintError(ASIOControlPanel()) != ASE_OK;
			}

			struct ChannelCounts {
				long input;
				long output;
			};

			ChannelCounts GetChannels() {
				Log(false) << "Querying driver for channel count...";
				Log() << "ASIOGetChannels()";
				long numInputChannels, numOutputChannels;
				const auto error = PrintError(ASIOGetChannels(&numInputChannels, &numOutputChannels));
				if (error != ASE_OK) return { 0, 0 };
				Log(false) << "..." << numInputChannels << " input channels, " << numOutputChannels << " output channels";
				return { numInputChannels, numOutputChannels };
			}

			struct BufferSize {
				long min = LONG_MIN;
				long max = LONG_MIN;
				long preferred = LONG_MIN;
				long granularity = LONG_MIN;
			};

			std::optional<BufferSize> GetBufferSize() {
				Log(false) << "Querying driver for buffer size suggestions...";
				Log() << "ASIOGetBufferSize()";
				BufferSize bufferSize;
				const auto error = PrintError(ASIOGetBufferSize(&bufferSize.min, &bufferSize.max, &bufferSize.preferred, &bufferSize.granularity));
				if (error != ASE_OK) return std::nullopt;
				Log(false) << "...suggested buffer sizes (in samples): min " << bufferSize.min << " max " << bufferSize.max << " preferred " << bufferSize.preferred << " granularity " << bufferSize.granularity;
				return bufferSize;
			}

			std::optional<ASIOSampleRate> GetSampleRate() {
				Log(false) << "Querying driver for current sample rate...";
				Log() << "ASIOGetSampleRate()";
				ASIOSampleRate sampleRate = NAN;
				const auto error = PrintError(ASIOGetSampleRate(&sampleRate));
				if (error != ASE_OK) return std::nullopt;
				Log(false) << "...sample rate: " << sampleRate << " Hz";
				return sampleRate;
			}

			bool CanSampleRate(ASIOSampleRate sampleRate) {
				Log(false) << "Asking driver if it can do a " << sampleRate << " Hz sample rate...";
				Log() << "ASIOCanSampleRate(" << sampleRate << ")";
				auto can = PrintError(ASIOCanSampleRate(sampleRate)) == ASE_OK;
				Log(false) << (can ? "...yes it can" : "...no, it can't");
				return can;
			}

			bool SetSampleRate(ASIOSampleRate sampleRate) {
				Log(false) << "Asking driver to switch to a " << sampleRate << " Hz sample rate";
				Log() << "ASIOSetSampleRate(" << sampleRate << ")";
				return PrintError(ASIOSetSampleRate(sampleRate)) == ASE_OK;
			}

			bool OutputReady() {
				Log() << "ASIOOutputReady()";
				return PrintError(ASIOOutputReady()) == ASE_OK;
			}

			std::optional<ASIOChannelInfo> GetChannelInfo(long channel, ASIOBool isInput) {
				Log(false) << "Asking driver for information about " << (isInput ? "input" : "output") << " channel " << channel << "...";
				Log() << "ASIOGetChannelInfo(channel = " << channel << " isInput = " << isInput << ")";
				ASIOChannelInfo channelInfo;
				channelInfo.channel = channel;
				channelInfo.isInput = isInput;
				if (PrintError(ASIOGetChannelInfo(&channelInfo)) != ASE_OK) return std::nullopt;
				const auto sampleTypeString = ::dechamps_ASIOUtil::GetASIOSampleTypeString(channelInfo.type);
				Log(false) << "...name `" << channelInfo.name << "`, type " << sampleTypeString << ", " << (channelInfo.isActive ? "" : "in") << "active, group " << channelInfo.channelGroup;
				return channelInfo;
			}

			std::vector<ASIOChannelInfo> GetAllChannelInfo(const std::vector<long>& inputChannels, const std::vector<long>& outputChannels) {
				std::vector<ASIOChannelInfo> channelInfos;
				for (const auto& inputChannel : inputChannels) {
					const auto channelInfo = GetChannelInfo(inputChannel, true);
					if (channelInfo.has_value()) channelInfos.push_back(*channelInfo);
				}
				for (const auto& outputChannel : outputChannels) {
					const auto channelInfo = GetChannelInfo(outputChannel, false);
					if (channelInfo.has_value()) channelInfos.push_back(*channelInfo);
				}
				return channelInfos;
			}

			struct Buffers {
				Buffers() = default;
				explicit Buffers(std::vector<ASIOBufferInfo> info) : info(std::move(info)) {}
				Buffers(const Buffers&) = delete;
				Buffers(Buffers&&) = default;
				~Buffers() {
					if (info.size() == 0) return;
					Log(false);
					Log(false) << "Asking driver to exit prepared state";
					Log() << "ASIODisposeBuffers()";
					PrintError(ASIODisposeBuffers());
				}

				std::vector<ASIOBufferInfo> info;
			};

			Buffers CreateBuffers(const std::vector<long>& inputChannels, const std::vector<long>& outputChannels, long bufferSize, ASIOCallbacks callbacks) {
				std::vector<ASIOBufferInfo> bufferInfos;
				for (long inputChannel : inputChannels) {
					auto& bufferInfo = bufferInfos.emplace_back();
					bufferInfo.isInput = true;
					bufferInfo.channelNum = inputChannel;
				}
				for (long outputChannel : outputChannels) {
					auto& bufferInfo = bufferInfos.emplace_back();
					bufferInfo.isInput = false;
					bufferInfo.channelNum = outputChannel;
				}

				Log(false) << "Asking driver to prepare for streaming with a buffer size of " << bufferSize << " samples and the following channels:";
				for (const auto& bufferInfo : bufferInfos) {
					Log(false) << "- " << (bufferInfo.isInput ? "Input" : "Output") << " channel " << bufferInfo.channelNum;
				}

				Log() << "ASIOCreateBuffers(";
				for (const auto& bufferInfo : bufferInfos) {
					Log() << "isInput = " << bufferInfo.isInput << " channelNum = " << bufferInfo.channelNum << " ";
				}
				Log() << ", bufferSize = " << bufferSize << ", bufferSwitch = " << (void*)(callbacks.bufferSwitch) << " sampleRateDidChange = " << (void*)(callbacks.sampleRateDidChange) << " asioMessage = " << (void*)(callbacks.asioMessage) << " bufferSwitchTimeInfo = " << (void*)(callbacks.bufferSwitchTimeInfo) << ")";

				if (PrintError(ASIOCreateBuffers(bufferInfos.data(), long(bufferInfos.size()), bufferSize, &callbacks)) != ASE_OK) return {};
				return Buffers(bufferInfos);
			}

			void GetLatencies() {
				long inputLatency = LONG_MIN, outputLatency = LONG_MIN;
				Log(false) << "Querying latencies...";
				Log() << "ASIOGetLatencies()";
				if (PrintError(ASIOGetLatencies(&inputLatency, &outputLatency)) != ASE_OK) return;
				Log(false) << "..." << inputLatency << " samples input latency, " << outputLatency << " samples output latency";
			}

			bool Start() {
				Log(false) << "Asking driver to start streaming";
				Log() << "ASIOStart()";
				return PrintError(ASIOStart()) == ASE_OK;
			}

			bool Stop() {
				Log(false) << "Asking driver to stop streaming";
				Log() << "ASIOStop()";
				return PrintError(ASIOStop()) == ASE_OK;
			}

			void GetSamplePosition() {
				Log() << "ASIOGetSamplePosition()";
				ASIOSamples samples;
				ASIOTimeStamp timeStamp;
				if (PrintError(ASIOGetSamplePosition(&samples, &timeStamp)) != ASE_OK) return;
				Log() << "Sample position: " << ::dechamps_ASIOUtil::ASIOToInt64(samples) << " timestamp: " << ::dechamps_ASIOUtil::ASIOToInt64(timeStamp);
			}

			long HandleASIOMessage(long selector, long value, void* message, double* opt) {
				const auto handler = ::dechamps_cpputil::Find(selector, message_selector_handlers);
				if (!handler.has_value()) return 0;
				return (*handler)(selector, value, message, opt);
			}

			// Allows the use of capturing lambdas for ASIO callbacks, even though ASIO doesn't provide any mechanism to pass user context to callbacks.
			// This works by assuming that we will only use one set of callbacks at a time, such that we can use global state as a side channel.
			struct Callbacks {
				Callbacks() {
					if (global != nullptr) abort();
					global = this;
				}
				~Callbacks() {
					if (global != this) abort();
					global = nullptr;
				}

				function_pointer_traits<decltype(ASIOCallbacks::bufferSwitch)>::function bufferSwitch;
				function_pointer_traits<decltype(ASIOCallbacks::sampleRateDidChange)>::function sampleRateDidChange;
				function_pointer_traits<decltype(ASIOCallbacks::asioMessage)>::function asioMessage;
				function_pointer_traits<decltype(ASIOCallbacks::bufferSwitchTimeInfo)>::function bufferSwitchTimeInfo;

				ASIOCallbacks GetASIOCallbacks() const {
					ASIOCallbacks callbacks;
					callbacks.bufferSwitch = GetASIOCallback<&Callbacks::bufferSwitch>();
					callbacks.sampleRateDidChange = GetASIOCallback<&Callbacks::sampleRateDidChange>();
					callbacks.asioMessage = GetASIOCallback<&Callbacks::asioMessage>();
					callbacks.bufferSwitchTimeInfo = GetASIOCallback<&Callbacks::bufferSwitchTimeInfo>();
					return callbacks;
				}

			private:
				template <auto memberFunction> auto GetASIOCallback() const {
					return [](auto... args) {
						if (global == nullptr) abort();
						return (global->*memberFunction)(args...);
					};
				}

				static Callbacks* global;
			};

			bool RunInitialized() {
				if (!Init()) return false;

				Log(false);

				if (config.openControlPanel) {
					return ControlPanel();
				}

				const auto availableChannelCounts = GetChannels();
				const auto inputChannels = PopulateChannels(config.inputChannels, availableChannelCounts.input, "Input");
				const auto outputChannels = PopulateChannels(config.outputChannels, availableChannelCounts.output, "Output");

				Log(false);

				GetLatencies();

				Log(false);

				auto initialSampleRate = GetSampleRate();
				if (!initialSampleRate.has_value()) return false;

				for (const auto sampleRate : { 44100.0, 48000.0, 96000.0, 192000.0 }) {
					if (CanSampleRate(sampleRate)) {
						if (!SetSampleRate(sampleRate)) return false;
						if (GetSampleRate() != sampleRate) return false;
					}
				}

				Log(false);

				const auto channelInfos = GetAllChannelInfo(inputChannels, outputChannels);
				if (channelInfos.size() != inputChannels.size() + outputChannels.size()) return false;

				Log(false);

				auto targetSampleRate = config.sampleRate;

				std::optional<std::vector<uint8_t>> playbackData;
				std::optional<size_t> playbackSampleSize;
				if (config.playbackFromFile.has_value()) {
					const auto inputSampleType = GetCommonSampleType(channelInfos, /*input=*/false);
					playbackSampleSize = ::dechamps_ASIOUtil::GetASIOSampleSize(inputSampleType);
					if (!playbackSampleSize.has_value()) throw std::runtime_error("Cannot determine size of playback sample type " + ::dechamps_ASIOUtil::GetASIOSampleTypeString(inputSampleType));

					Log() << "Loading playback file";
					try {
						PlaybackFile playbackFile(*config.playbackFromFile);
						const auto playbackSampleRate = playbackFile.SampleRate();
						if (!targetSampleRate.has_value()) targetSampleRate = playbackSampleRate;
						playbackFile.Validate(int(*targetSampleRate), int(outputChannels.size()), inputSampleType);

						playbackData = playbackFile.Read();
					}
					catch (const std::exception& exception) {
						throw std::runtime_error(std::string("Cannot playback from file: ") + exception.what());
					}
					Log() << "Playback file loading complete (" << playbackData->size() << " bytes)";
					Log();
				}

				if (!targetSampleRate.has_value()) targetSampleRate = *initialSampleRate;

				std::optional<std::vector<uint8_t>> recordData;
				std::optional<ASIOSampleType> recordSampleType;
				std::optional<size_t> recordSampleSize;
				if (config.recordToFile.has_value()) {
					recordSampleType = GetCommonSampleType(channelInfos, /*input=*/true);
					recordSampleSize = ::dechamps_ASIOUtil::GetASIOSampleSize(*recordSampleType);
					if (!recordSampleSize.has_value()) throw std::runtime_error("Cannot determine size of record sample type " + ::dechamps_ASIOUtil::GetASIOSampleTypeString(*recordSampleType));
					recordData.emplace();
				}

				if (!CanSampleRate(*targetSampleRate)) return false;
				if (!SetSampleRate(*targetSampleRate)) return false;
				if (GetSampleRate() != *targetSampleRate) return false;

				Log(false);

				const auto bufferSize = GetBufferSize();
				if (!bufferSize.has_value()) return false;
				const auto bufferSizeFrames = config.bufferSizeFrames.has_value() ? *config.bufferSizeFrames : bufferSize->preferred;

				size_t maxBufferSwitchCount = config.defaultBufferSwitchCount;
				if (config.bufferSwitchCount.has_value()) maxBufferSwitchCount = *config.bufferSwitchCount;
				else if (playbackData.has_value()) {
					const auto frameSize = *playbackSampleSize * outputChannels.size();
					if (playbackData->size() % frameSize != 0) throw std::runtime_error("Input ends in the middle of a frame");
					const auto inputSizeInFrames = playbackData->size() / frameSize;
					maxBufferSwitchCount = inputSizeInFrames / bufferSizeFrames;
					if (inputSizeInFrames % bufferSizeFrames != 0) ++maxBufferSwitchCount;
				}
				else maxBufferSwitchCount = config.defaultBufferSwitchCount;
				Log() << "Will stop after " << maxBufferSwitchCount << " buffer switches";

				if (playbackData.has_value()) {
					const auto inputFrameSize = *playbackSampleSize * outputChannels.size();
					playbackData->resize(inputFrameSize * bufferSizeFrames * maxBufferSwitchCount);
				}
				if (recordData.has_value()) {
					const auto outputFrameSize = *recordSampleSize * inputChannels.size();
					// Fill the memory to force the operating system to actually commit the pages.
					recordData->resize(outputFrameSize * bufferSizeFrames * maxBufferSwitchCount, 0x88);
					recordData->clear();
				}

				Log(false);

				Callbacks callbacks;
				callbacks.bufferSwitch = [&](long doubleBufferIndex, ASIOBool directProcess) {
					Log() << "bufferSwitch(doubleBufferIndex = " << doubleBufferIndex << ", directProcess = " << directProcess << ") called before start!";
					Log() << "<- ";
				};
				callbacks.bufferSwitchTimeInfo = [&](ASIOTime* params, long doubleBufferIndex, ASIOBool directProcess) {
					Log() << "bufferSwitchTimeInfo(params = (" << (params == nullptr ? "none" : ::dechamps_ASIOUtil::DescribeASIOTime(*params)) << "), doubleBufferIndex = " << doubleBufferIndex << ", directProcess = " << directProcess << ") called before start!";
					Log() << "<- nullptr";
					return nullptr;
				};
				callbacks.sampleRateDidChange = [&](ASIOSampleRate sampleRate) {
					Log() << "sampleRateDidChange(" << sampleRate << ")";
					Log() << "<-";
				};
				callbacks.asioMessage = [&](long selector, long value, void* message, double* opt) {
					Log() << "asioMessage(selector = " << ::dechamps_ASIOUtil::GetASIOMessageSelectorString(selector) << ", value = " << value << ", message = " << message << ", opt = " << opt << ")";
					const auto result = HandleASIOMessage(selector, value, message, opt);
					Log() << "<- " << result;
					return result;
				};

				const auto buffers = CreateBuffers(inputChannels, outputChannels, bufferSizeFrames, callbacks.GetASIOCallbacks());
				if (buffers.info.size() == 0) return false;

				enum class Outcome { SUCCESS, FAILURE };

				std::mutex outcomeMutex;
				std::optional<Outcome> outcome;
				std::condition_variable outcomeCondition;
				const auto setOutcome = [&](Outcome newOutcome) {
					{
						std::scoped_lock outcomeLock(outcomeMutex);
						if (outcome.has_value()) return;
						outcome = newOutcome;
					}
					outcomeCondition.notify_all();
				};

				if (maxBufferSwitchCount == 0) setOutcome(Outcome::SUCCESS);

				size_t bufferSwitchCount = 0;
				const auto incrementBufferSwitchCount = [&] {
					++bufferSwitchCount;
					Log(false) << "Streaming buffer " << bufferSwitchCount << "/" << maxBufferSwitchCount;
					if (bufferSwitchCount >= maxBufferSwitchCount) setOutcome(Outcome::SUCCESS);
				};

				auto playback = [&](long doubleBufferIndex, size_t bufferOffset) {
					if (!playbackData.has_value() || bufferOffset >= maxBufferSwitchCount) return;
					const auto interleavedBufferSizeInBytes = outputChannels.size() * bufferSizeFrames * *playbackSampleSize;
					const auto inputStart = playbackData->data() + bufferOffset * interleavedBufferSizeInBytes;
					CopyFromInterleavedBuffer(buffers.info, *playbackSampleSize, bufferSizeFrames, doubleBufferIndex, inputStart, long(outputChannels.size()));
				};
				auto record = [&](long doubleBufferIndex) {
					if (!recordData.has_value()) return;
					const auto interleavedBufferSizeInBytes = inputChannels.size() * bufferSizeFrames * *recordSampleSize;
					recordData->resize(recordData->size() + interleavedBufferSizeInBytes);
					CopyToInterleavedBuffer(buffers.info, *recordSampleSize, bufferSizeFrames, doubleBufferIndex, recordData->data() + recordData->size() - interleavedBufferSizeInBytes, long(inputChannels.size()));
				};

				auto bufferSwitch = [&](long doubleBufferIndex) {
					try {
						GetSamplePosition();
						
						if (config.bufferSwitchDelayMs > 0) {
							Log() << "Sleeping for " << config.bufferSwitchDelayMs << " milliseconds";
							std::this_thread::sleep_for(std::chrono::duration<decltype(config.bufferSwitchDelayMs), std::milli>(config.bufferSwitchDelayMs));
						}

						playback(doubleBufferIndex, bufferSwitchCount + 1);  // +1 because the first buffer was provided before the first call to bufferSwitch()
						if (!config.inhibitOutputReady) OutputReady();
						record(doubleBufferIndex);

						incrementBufferSwitchCount();
					}
					catch (const std::exception& exception) {
						Log() << "FATAL ERROR: " << exception.what();
						setOutcome(Outcome::FAILURE);
					}
				};

				callbacks.bufferSwitch = [&](long doubleBufferIndex, ASIOBool directProcess) {
					Log() << "bufferSwitch(doubleBufferIndex = " << doubleBufferIndex << ", directProcess = " << directProcess << ")";
					bufferSwitch(doubleBufferIndex);
					Log() << "<-";
				};
				callbacks.bufferSwitchTimeInfo = [&](ASIOTime* params, long doubleBufferIndex, ASIOBool directProcess) {
					Log() << "bufferSwitchTimeInfo(params = (" << (params == nullptr ? "none" : ::dechamps_ASIOUtil::DescribeASIOTime(*params)) << "), doubleBufferIndex = " << doubleBufferIndex << ", directProcess = " << directProcess << ")";
					bufferSwitch(doubleBufferIndex);
					Log() << "<- nullptr";
					return nullptr;
				};

				Log(false);

				GetSampleRate();
				GetAllChannelInfo(inputChannels, outputChannels);

				Log(false);

				GetLatencies();

				Log(false);

				playback(1, 0);
				if (!config.inhibitOutputReady) {
					OutputReady();
					GetLatencies();
					Log(false);
				}

				if (!Start()) return false;

				Log(false);

				// List available sample rates while the stream is running.
				// This can help troubleshoot issues such as https://github.com/dechamps/FlexASIO/issues/66
				for (const auto sampleRate : { 44100.0, 48000.0, 96000.0, 192000.0 }) {
					CanSampleRate(sampleRate);
				}

				Log(false);

				{
					ConsoleCtrlHandler consoleCtrlHandler([&](DWORD) {
						Log() << "Caught control signal, aborting";
						setOutcome(Outcome::FAILURE);
						return TRUE;
					});
					std::unique_lock outcomeLock(outcomeMutex);
					outcomeCondition.wait(outcomeLock, [&] { return outcome.has_value();  });
				}

				Log(false);

				if (!Stop()) return false;

				if (recordData.has_value()) {
					Log() << "Writing record file (" << recordData->size() << " bytes)";
					try {
						RecordFile recordFile(*config.recordToFile, int(*targetSampleRate), int(inputChannels.size()), *recordSampleType);
						recordFile.Write(*recordData);
					}
					catch (const std::exception& exception) {
						throw std::runtime_error(std::string("Cannot record to file: ") + exception.what());
					}
					Log() << "Record file writing complete";
					Log();
				}

				// Note: we don't call ASIOExit() because it gets confused by our driver setup trickery (see InitAndRun()).
				return outcome == Outcome::SUCCESS;
			}

			const Config config;
		};

		ASIOTest::Callbacks* ASIOTest::Callbacks::global = nullptr;

	}
}

int ASIOTest_RunTest(IASIO* const asioDriver, int& argc, char**& argv) {
	if (asioDriver == nullptr) abort();

	const auto config = ::ASIOTest::GetConfig(argc, argv);
	if (!config.has_value()) return 2;

	// This basically does an end run around the ASIO host library driver loading system, simulating what loadAsioDriver() does.
	// This allows us to trick the ASIO host library into using a specific instance of an ASIO driver (the one this program is linked against),
	// as opposed to whatever ASIO driver might be currently installed on the system.
	theAsioDriver = asioDriver;
	const auto result = ::ASIOTest::ASIOTest(*config).Run();
	theAsioDriver = nullptr;

	return result ? 0 : 1;
}
