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

		struct Config {
			enum class LogMode { NONE, SYNC, ASYNC };

			// Run enough buffer switches such that we can trigger failure modes like https://github.com/dechamps/FlexASIO/issues/29.
			static constexpr size_t defaultBufferSwitchCount = 30;

			std::optional<long> bufferSizeFrames;
			std::optional<size_t> bufferSwitchCount;
			double bufferSwitchDelayMs = 0;
			bool inhibitOutputReady;
			std::optional<std::string> inputFile;
			LogMode logMode;
			std::optional<std::string> outputFile;
			std::optional<double> sampleRate;
		};

		std::optional<Config> GetConfig(int& argc, char**& argv) {
			cxxopts::Options options("ASIOTest", "ASIO driver test program");
			Config config;
			std::string logMode = "async";
			options.add_options()
				("buffer-size-frames", "ASIO buffer size to use, in frames; default is to use the preferred size suggested by the driver", cxxopts::value(config.bufferSizeFrames))
				("buffer-switch-count", "Stop after this many ASIO buffers have been switched; default is to stop when reaching the end of the input file, if any; otherwise, " + std::to_string(config.defaultBufferSwitchCount), cxxopts::value(config.bufferSwitchCount))
				("buffer-switch-delay-ms", "Sleep for this many milliseconds before processing a buffer switch callback; default is " + std::to_string(config.bufferSwitchDelayMs), cxxopts::value(config.bufferSwitchDelayMs))
				("inhibit-output-ready", "Don't call ASIOOutputReady() to inform the driver when the output buffer has been filled.", cxxopts::value(config.inhibitOutputReady))
				("input-file", "Preload the specified audio file, then play the untouched raw audio buffers to the ASIO driver.", cxxopts::value(config.inputFile))
				("log-mode", "How to output the log; can be 'none' (do not output the log, maximum performance), 'sync' (output the log synchronously, useful for debugging crashes) or 'async' (output the log asynchronously, useful to prevent slow output from affecting real time operation); default is '" + logMode + "'", cxxopts::value(logMode))
				("output-file", "Record untouched raw audio buffers from the ASIO driver, then write them to the specified file; output format is WAV for little-endian sample types (ASIOST*LSB), AIFF for big-endian sample types (ASIOST*MSB).", cxxopts::value(config.outputFile))
				("sample-rate", "ASIO sample rate to use; default is to use the input file sample rate, if any, otherwise the initial sample rate of the driver", cxxopts::value(config.sampleRate));
			try {
				options.parse(argc, argv);

				if (logMode == "none") config.logMode = Config::LogMode::NONE;
				else if (logMode == "sync") config.logMode = Config::LogMode::SYNC;
				else if (logMode == "async") config.logMode = Config::LogMode::ASYNC;
				else throw std::runtime_error("Invalid --log-mode setting");
			}
			catch (const cxxopts::OptionParseException& exception) {
				std::cerr << "USAGE ERROR: " << exception.what() << std::endl;
				std::cerr << std::endl;
				std::cerr << options.help() << std::endl;
				return std::nullopt;
			}
			return config;
		}

		class NoneLogState final {
		public:
			::dechamps_cpplog::LogSink* sink() { return nullptr; }
		};

		class SyncLogState final {
		public:
			::dechamps_cpplog::LogSink* sink() { return &preamble_sink; }

		private:
			::dechamps_cpplog::StreamLogSink stream_sink{ std::cout };
			::dechamps_cpplog::ThreadSafeLogSink thread_safe_sink{ stream_sink };
			::dechamps_cpplog::PreambleLogSink preamble_sink{ thread_safe_sink };
		};

		class AsyncLogState final {
		public:
			::dechamps_cpplog::LogSink* sink() { return &preamble_sink; }

		private:
			::dechamps_cpplog::StreamLogSink stream_sink{ std::cout };
			::dechamps_cpplog::AsyncLogSink async_sink{ stream_sink };
			::dechamps_cpplog::PreambleLogSink preamble_sink{ async_sink };
		};

		static std::optional<std::variant<NoneLogState, SyncLogState, AsyncLogState>> logState;

		::dechamps_cpplog::Logger Log() {
			if (!logState.has_value()) abort();
			return ::dechamps_cpplog::Logger(std::visit([](auto& logState) { return logState.sink(); }, *logState));
		}

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

		class InputFile {
		public:
			InputFile(const std::string_view path) : sndfile(OpenSndfile(path, SFM_READ)) {}

			int SampleRate() const { return sndfile.second.samplerate; }

			void Validate(const int sampleRate, const int channels, const ASIOSampleType sampleType) const {
				if (sndfile.second.samplerate != sampleRate) throw std::runtime_error("Input file sample rate mismatch: expected " + std::to_string(sampleRate) + ", got " + std::to_string(sndfile.second.samplerate));
				if (sndfile.second.channels != channels) throw std::runtime_error("Input file channel count mismatch: expected " + std::to_string(channels) + ", got " + std::to_string(sndfile.second.channels));
				const auto fileSampleType = SfFormatToASIOSampleType(sndfile.second.format, GetSndfileEndianness(sndfile.first.get()));
				if (!fileSampleType.has_value()) throw std::runtime_error("Unrecognized input file sample type");
				if (*fileSampleType != sampleType) throw std::runtime_error("Input file sample type mismatch: expected " + ::dechamps_ASIOUtil::GetASIOSampleTypeString(sampleType) + ", got " + ::dechamps_ASIOUtil::GetASIOSampleTypeString(*fileSampleType));
			}

			std::vector<uint8_t> Read() {
				constexpr auto readSizeBytes = 4096;
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

		class OutputFile {
		public:
			OutputFile(const std::string_view path, const int sampleRate, const int channels, const ASIOSampleType sampleType) :
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
			Log() << "-> " << ::dechamps_ASIOUtil::GetASIOErrorString(error);
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
				switch (config.logMode) {
				case Config::LogMode::NONE: logState.emplace(std::in_place_type<NoneLogState>); break;
				case Config::LogMode::SYNC: logState.emplace(std::in_place_type<SyncLogState>); break;
				case Config::LogMode::ASYNC: logState.emplace(std::in_place_type<AsyncLogState>); break;
				}
			}
			~ASIOTest() {
				if (!logState.has_value()) abort();
				logState.reset();
			}

			bool Run() {
				try {
					return RunInitialized();
				}
				catch (const std::exception& exception) {
					Log() << "FATAL ERROR: " << exception.what();
					return false;
				}
			}

		private:
			std::optional<ASIODriverInfo> Init() {
				ASIODriverInfo asioDriverInfo = { 0 };
				asioDriverInfo.asioVersion = 2;
				Log() << "ASIOInit(asioVersion = " << asioDriverInfo.asioVersion << ")";
				const auto initError = PrintError(ASIOInit(&asioDriverInfo));
				Log() << "asioVersion = " << asioDriverInfo.asioVersion << " driverVersion = " << asioDriverInfo.asioVersion << " name = " << asioDriverInfo.name << " errorMessage = " << asioDriverInfo.errorMessage << " sysRef = " << asioDriverInfo.sysRef;
				if (initError != ASE_OK) return std::nullopt;
				return asioDriverInfo;
			}

			std::pair<long, long> GetChannels() {
				Log() << "ASIOGetChannels()";
				long numInputChannels, numOutputChannels;
				const auto error = PrintError(ASIOGetChannels(&numInputChannels, &numOutputChannels));
				if (error != ASE_OK) return { 0, 0 };
				Log() << "Channel count: " << numInputChannels << " input, " << numOutputChannels << " output";
				return { numInputChannels, numOutputChannels };
			}

			struct BufferSize {
				long min = LONG_MIN;
				long max = LONG_MIN;
				long preferred = LONG_MIN;
				long granularity = LONG_MIN;
			};

			std::optional<BufferSize> GetBufferSize() {
				Log() << "ASIOGetBufferSize()";
				BufferSize bufferSize;
				const auto error = PrintError(ASIOGetBufferSize(&bufferSize.min, &bufferSize.max, &bufferSize.preferred, &bufferSize.granularity));
				if (error != ASE_OK) return std::nullopt;
				Log() << "Buffer size: min " << bufferSize.min << " max " << bufferSize.max << " preferred " << bufferSize.preferred << " granularity " << bufferSize.granularity;
				return bufferSize;
			}

			std::optional<ASIOSampleRate> GetSampleRate() {
				Log() << "ASIOGetSampleRate()";
				ASIOSampleRate sampleRate = NAN;
				const auto error = PrintError(ASIOGetSampleRate(&sampleRate));
				if (error != ASE_OK) return std::nullopt;
				Log() << "Sample rate: " << sampleRate;
				return sampleRate;
			}

			bool CanSampleRate(ASIOSampleRate sampleRate) {
				Log() << "ASIOCanSampleRate(" << sampleRate << ")";
				return PrintError(ASIOCanSampleRate(sampleRate)) == ASE_OK;
			}

			bool SetSampleRate(ASIOSampleRate sampleRate) {
				Log() << "ASIOSetSampleRate(" << sampleRate << ")";
				return PrintError(ASIOSetSampleRate(sampleRate)) == ASE_OK;
			}

			bool OutputReady() {
				Log() << "ASIOOutputReady()";
				return PrintError(ASIOOutputReady()) == ASE_OK;
			}

			std::optional<ASIOChannelInfo> GetChannelInfo(long channel, ASIOBool isInput) {
				Log() << "ASIOGetChannelInfo(channel = " << channel << " isInput = " << isInput << ")";
				ASIOChannelInfo channelInfo;
				channelInfo.channel = channel;
				channelInfo.isInput = isInput;
				if (PrintError(ASIOGetChannelInfo(&channelInfo)) != ASE_OK) return std::nullopt;
				Log() << "isActive = " << channelInfo.isActive << " channelGroup = " << channelInfo.channelGroup << " type = " << ::dechamps_ASIOUtil::GetASIOSampleTypeString(channelInfo.type) << " name = " << channelInfo.name;
				return channelInfo;
			}

			std::vector<ASIOChannelInfo> GetAllChannelInfo(std::pair<long, long> ioChannelCounts) {
				std::vector<ASIOChannelInfo> channelInfos;
				for (long inputChannel = 0; inputChannel < ioChannelCounts.first; ++inputChannel) {
					const auto channelInfo = GetChannelInfo(inputChannel, true);
					if (channelInfo.has_value()) channelInfos.push_back(*channelInfo);
				}
				for (long outputChannel = 0; outputChannel < ioChannelCounts.second; ++outputChannel) {
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
					Log();
					Log() << "ASIODisposeBuffers()";
					PrintError(ASIODisposeBuffers());
				}

				std::vector<ASIOBufferInfo> info;
			};

			// TODO: we should also test with not all channels active.
			Buffers CreateBuffers(std::pair<long, long> ioChannelCounts, long bufferSize, ASIOCallbacks callbacks) {
				std::vector<ASIOBufferInfo> bufferInfos;
				for (long inputChannel = 0; inputChannel < ioChannelCounts.first; ++inputChannel) {
					auto& bufferInfo = bufferInfos.emplace_back();
					bufferInfo.isInput = true;
					bufferInfo.channelNum = inputChannel;
				}
				for (long outputChannel = 0; outputChannel < ioChannelCounts.second; ++outputChannel) {
					auto& bufferInfo = bufferInfos.emplace_back();
					bufferInfo.isInput = false;
					bufferInfo.channelNum = outputChannel;
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
				Log() << "ASIOGetLatencies()";
				if (PrintError(ASIOGetLatencies(&inputLatency, &outputLatency)) != ASE_OK) return;
				Log() << "Latencies: input " << inputLatency << " samples, output " << outputLatency << " samples";
			}

			bool Start() {
				Log() << "ASIOStart()";
				return PrintError(ASIOStart()) == ASE_OK;
			}

			bool Stop() {
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

				Log();

				const auto ioChannelCounts = GetChannels();
				if (ioChannelCounts.first == 0 && ioChannelCounts.second == 0) return false;

				Log();

				auto initialSampleRate = GetSampleRate();
				if (!initialSampleRate.has_value()) return false;

				for (const auto sampleRate : { 44100.0, 48000.0, 96000.0, 192000.0 }) {
					if (CanSampleRate(sampleRate)) {
						if (!SetSampleRate(sampleRate)) return false;
						if (GetSampleRate() != sampleRate) return false;
					}
				}

				Log();

				const auto channelInfos = GetAllChannelInfo(ioChannelCounts);
				if (long(channelInfos.size()) != ioChannelCounts.first + ioChannelCounts.second) return false;

				Log();

				auto targetSampleRate = config.sampleRate;

				std::optional<std::vector<uint8_t>> inputData;
				std::optional<size_t> inputSampleSize;
				if (config.inputFile.has_value()) {
					const auto inputSampleType = GetCommonSampleType(channelInfos, /*input=*/false);
					inputSampleSize = ::dechamps_ASIOUtil::GetASIOSampleSize(inputSampleType);
					if (!inputSampleSize.has_value()) throw std::runtime_error("Cannot determine size of input sample type " + ::dechamps_ASIOUtil::GetASIOSampleTypeString(inputSampleType));

					Log() << "Loading input file";
					try {
						InputFile inputFile(*config.inputFile);
						const auto inputFileSampleRate = inputFile.SampleRate();
						if (!targetSampleRate.has_value()) targetSampleRate = inputFileSampleRate;
						inputFile.Validate(int(*targetSampleRate), ioChannelCounts.second, inputSampleType);

						inputData = inputFile.Read();
					}
					catch (const std::exception& exception) {
						throw std::runtime_error(std::string("Cannot input from file: ") + exception.what());
					}
					Log() << "Input file loading complete (" << inputData->size() << " bytes)";
					Log();
				}

				if (!targetSampleRate.has_value()) targetSampleRate = *initialSampleRate;

				std::optional<std::vector<uint8_t>> outputData;
				std::optional<ASIOSampleType> outputSampleType;
				std::optional<size_t> outputSampleSize;
				if (config.outputFile.has_value()) {
					outputSampleType = GetCommonSampleType(channelInfos, /*input=*/true);
					outputSampleSize = ::dechamps_ASIOUtil::GetASIOSampleSize(*outputSampleType);
					if (!outputSampleSize.has_value()) throw std::runtime_error("Cannot determine size of output sample type " + ::dechamps_ASIOUtil::GetASIOSampleTypeString(*outputSampleType));
					outputData.emplace();
				}

				if (!CanSampleRate(*targetSampleRate)) return false;
				if (!SetSampleRate(*targetSampleRate)) return false;
				if (GetSampleRate() != *targetSampleRate) return false;

				Log();

				const auto bufferSize = GetBufferSize();
				if (!bufferSize.has_value()) return false;
				const auto bufferSizeFrames = config.bufferSizeFrames.has_value() ? *config.bufferSizeFrames : bufferSize->preferred;

				size_t maxBufferSwitchCount = config.defaultBufferSwitchCount;
				if (config.bufferSwitchCount.has_value()) maxBufferSwitchCount = *config.bufferSwitchCount;
				else if (inputData.has_value()) {
					const auto frameSize = *inputSampleSize * ioChannelCounts.second;
					if (inputData->size() % frameSize != 0) throw std::runtime_error("Input ends in the middle of a frame");
					const auto inputSizeInFrames = inputData->size() / frameSize;
					maxBufferSwitchCount = inputSizeInFrames / bufferSizeFrames;
					if (inputSizeInFrames % bufferSizeFrames != 0) ++maxBufferSwitchCount;
				}
				else maxBufferSwitchCount = config.defaultBufferSwitchCount;
				Log() << "Will stop after " << maxBufferSwitchCount << " buffer switches";

				if (inputData.has_value()) {
					const auto inputFrameSize = *inputSampleSize * ioChannelCounts.second;
					inputData->resize(inputFrameSize * bufferSizeFrames * maxBufferSwitchCount);
				}
				if (outputData.has_value()) {
					const auto outputFrameSize = *outputSampleSize * ioChannelCounts.first;
					// Fill the memory to force the operating system to actually commit the pages.
					outputData->resize(outputFrameSize * bufferSizeFrames * maxBufferSwitchCount, 0x88);
					outputData->clear();
				}

				Log();

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

				const auto buffers = CreateBuffers(ioChannelCounts, bufferSizeFrames, callbacks.GetASIOCallbacks());
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
					Log() << "Buffer switch count: " << bufferSwitchCount << "/" << maxBufferSwitchCount;
					if (bufferSwitchCount >= maxBufferSwitchCount) setOutcome(Outcome::SUCCESS);
				};

				auto playback = [&](long doubleBufferIndex) {
					if (!inputData.has_value() || bufferSwitchCount >= maxBufferSwitchCount) return;
					const auto interleavedBufferSizeInBytes = ioChannelCounts.second * bufferSizeFrames * *inputSampleSize;
					const auto inputStart = inputData->data() + bufferSwitchCount * interleavedBufferSizeInBytes;
					::dechamps_ASIOUtil::CopyFromInterleavedBuffer(buffers.info, false, *inputSampleSize, bufferSizeFrames, doubleBufferIndex, inputStart, ioChannelCounts.second);
				};
				auto record = [&](long doubleBufferIndex) {
					if (!outputData.has_value()) return;
					const auto interleavedBufferSizeInBytes = ioChannelCounts.first * bufferSizeFrames * *outputSampleSize;
					outputData->resize(outputData->size() + interleavedBufferSizeInBytes);
					::dechamps_ASIOUtil::CopyToInterleavedBuffer(buffers.info, true, *outputSampleSize, bufferSizeFrames, doubleBufferIndex, outputData->data() + outputData->size() - interleavedBufferSizeInBytes, ioChannelCounts.first);
				};

				auto bufferSwitch = [&](long doubleBufferIndex) {
					try {
						GetSamplePosition();
						
						if (config.bufferSwitchDelayMs > 0) {
							Log() << "Sleeping for " << config.bufferSwitchDelayMs << " milliseconds";
							std::this_thread::sleep_for(std::chrono::duration<decltype(config.bufferSwitchDelayMs), std::milli>(config.bufferSwitchDelayMs));
						}

						playback(doubleBufferIndex);
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

				Log();

				GetSampleRate();
				GetAllChannelInfo(ioChannelCounts);

				Log();

				GetLatencies();

				Log();

				playback(1);
				if (!config.inhibitOutputReady) {
					OutputReady();
					GetLatencies();
					Log();
				}

				if (!Start()) return false;

				Log();

				{
					ConsoleCtrlHandler consoleCtrlHandler([&](DWORD) {
						Log() << "Caught control signal, aborting";
						setOutcome(Outcome::FAILURE);
						return TRUE;
					});
					std::unique_lock outcomeLock(outcomeMutex);
					outcomeCondition.wait(outcomeLock, [&] { return outcome.has_value();  });
				}

				Log();

				if (!Stop()) return false;

				if (outputData.has_value()) {
					Log() << "Writing output file (" << outputData->size() << " bytes)";
					try {
						OutputFile outputFile(*config.outputFile, int(*targetSampleRate), ioChannelCounts.first, *outputSampleType);
						outputFile.Write(*outputData);
					}
					catch (const std::exception& exception) {
						throw std::runtime_error(std::string("Cannot output to file: ") + exception.what());
					}
					Log() << "Output file writing complete";
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
