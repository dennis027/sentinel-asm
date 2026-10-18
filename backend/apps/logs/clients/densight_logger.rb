# Send a Ruby application's logs to Densight. Standard library only (Ruby 3.2+).
#
#   require_relative "densight_logger"
#   logger = Densight::Logger.new(url: ENV["DENSIGHT_URL"], key: ENV["DENSIGHT_KEY"], service: "shop", io: $stdout)
#   logger.info("order placed", order_id: 42)
#   logger.error(exception)                       # sent with its class and backtrace
#
# Rails (config/initializers/densight.rb, file in lib/):
#
#   require Rails.root.join("lib/densight_logger")
#   Rails.application.configure do
#     config.logger = ActiveSupport::TaggedLogging.new(
#       Densight::Logger.new(url: ENV["DENSIGHT_URL"], key: ENV["DENSIGHT_KEY"], service: "shop", io: $stdout))
#   end
#   # Unhandled exceptions, with their backtrace (Rails 7.1+):
#   Rails.error.subscribe(Densight::ErrorSubscriber.new(Rails.logger))
#
# It is a normal ::Logger (still writes to `io` if given); records are queued
# and sent in batches from a background thread, so logging never slows a
# request and a Densight outage never raises inside the application.
# `release:` (or DENSIGHT_RELEASE) names the version running.

require "json"
require "logger"
require "net/http"
require "socket"
require "time"
require "uri"

module Densight
  class Logger < ::Logger
    LEVELS = %w[DEBUG INFO WARN ERROR FATAL ANY].freeze

    def initialize(url:, key:, service: "", environment: "", release: ENV.fetch("DENSIGHT_RELEASE", ""),
                   io: nil, batch_size: 200, flush_interval: 2.0, level: ::Logger::DEBUG)
      super(io || File::NULL, level: level)
      @uri = URI(url)
      @key = key
      @base = { service: service, environment: environment, release: release, host: Socket.gethostname }
      @batch_size = batch_size
      @flush_interval = flush_interval
      @queue = Queue.new
      @pid = Process.pid
      start_sender
      at_exit { flush }
    end

    # Logger#add is what debug/info/warn/error/fatal all call.
    def add(severity, message = nil, progname = nil, &block)
      severity ||= ::Logger::UNKNOWN
      return true if severity < level

      if message.nil?
        if block
          message = block.call
        else
          message = progname
          progname = @progname
        end
      end
      enqueue(severity, message, progname)
      super(severity, message, progname)
    end

    # logger.info("order placed", order_id: 42): extra fields as keyword arguments.
    %i[debug info warn error fatal].each do |name|
      define_method(name) do |message = nil, **fields, &block|
        severity = ::Logger.const_get(name.upcase)
        return true if severity < level

        message = block.call if message.nil? && block
        enqueue(severity, message, progname, fields)
        ::Logger.instance_method(:add).bind_call(self, severity, message, progname)
      end
    end

    def flush
      send_batch(drain(10_000))
    end

    private

    def enqueue(severity, message, progname, fields = {})
      start_sender if @pid != Process.pid # forked (Puma/Unicorn workers, Sidekiq): threads don't survive fork
      entry = @base.merge(
        timestamp: Time.now.utc.iso8601(6),
        level: LEVELS[severity] || "ANY",
        logger: progname || "",
      )
      tags = Thread.current[:activesupport_tagged_logging_tags] || []
      entry[:tags] = tags.dup unless tags.empty?
      if message.is_a?(Exception)
        entry[:message] = "#{message.class}: #{message.message}"
        entry[:exception] = exception_of(message)
      else
        entry[:message] = message.is_a?(String) ? message : message.inspect
        if (error = fields.delete(:exception) || fields.delete(:error)).is_a?(Exception)
          entry[:exception] = exception_of(error)
        end
      end
      fields.each { |k, v| entry[k] = v unless entry.key?(k) }
      @queue << entry if @queue.size < 20_000
    rescue StandardError
      nil # logging must never break the application
    end

    def exception_of(error)
      stack = "#{error.class}: #{error.message}\n#{Array(error.backtrace).first(60).join("\n")}"
      stack += "\nCaused by: #{error.cause.class}: #{error.cause.message}" if error.cause
      { type: error.class.name, value: error.message, stacktrace: stack }
    end

    def start_sender
      @pid = Process.pid
      @queue = Queue.new
      @thread = Thread.new do
        loop do
          batch = [@queue.pop]
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + @flush_interval
          while batch.size < @batch_size
            remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            break if remaining <= 0

            item = @queue.pop(timeout: remaining)
            break if item.nil?

            batch << item
          end
          send_batch(batch)
        end
      end
    end

    def drain(limit)
      items = []
      items << @queue.pop(true) while items.size < limit && !@queue.empty?
      items
    rescue ThreadError
      items
    end

    def send_batch(batch)
      return if batch.nil? || batch.empty?

      http = Net::HTTP.new(@uri.host, @uri.port)
      http.use_ssl = @uri.scheme == "https"
      http.open_timeout = http.read_timeout = 5
      request = Net::HTTP::Post.new(@uri.request_uri,
                                    "Authorization" => "Bearer #{@key}", "Content-Type" => "application/json")
      request.body = JSON.generate(batch)
      http.request(request)
    rescue StandardError
      nil # dropped: an unreachable Densight must not affect the application
    end
  end

  # Rails 7.1+: Rails.error.subscribe(Densight::ErrorSubscriber.new(Rails.logger))
  class ErrorSubscriber
    def initialize(logger)
      @logger = logger
    end

    def report(error, handled:, severity:, context:, source: nil)
      return if handled && severity == :info

      fields = { exception: error, handled: handled, source: source.to_s }
      @logger.respond_to?(:error) && @logger.error("#{error.class}: #{error.message}", **fields)
    rescue StandardError
      nil
    end
  end
end
