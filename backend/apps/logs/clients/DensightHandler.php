<?php
/**
 * Send a PHP application's logs to Densight: a Monolog handler (Monolog 2
 * or 3, so Laravel, Symfony and anything else using Monolog). No other
 * dependencies; uses curl when it is installed, PHP streams otherwise.
 *
 * Laravel (save as app/Logging/DensightHandler.php), config/logging.php:
 *
 *     'densight' => [
 *         'driver' => 'monolog',
 *         'handler' => App\Logging\DensightHandler::class,
 *         'with' => ['url' => env('DENSIGHT_URL'), 'key' => env('DENSIGHT_KEY'), 'service' => 'shop'],
 *         'level' => 'info',
 *     ],
 *
 * and add 'densight' to the 'stack' channel's 'channels'.
 *
 * Symfony (save as src/Logging/DensightHandler.php): register the class as a
 * service with $url, $key and $service arguments, and add a monolog handler
 * of `type: service` with that id.
 *
 * Anything else: $logger->pushHandler(new App\Logging\DensightHandler($url, $key, 'my-app'));
 *
 * Exceptions passed as context (`$logger->error('Payment failed', ['exception' => $e])`,
 * which Laravel and Symfony do for unhandled ones) are sent with their stack
 * trace. On a web request the method, path, client address and user agent are
 * added. Records are sent in one request when the PHP request ends (or every
 * $batchSize records); a Densight outage never throws inside the application.
 */

namespace App\Logging;

use Monolog\Handler\AbstractProcessingHandler;

class DensightHandler extends AbstractProcessingHandler
{
    private array $buffer = [];
    private string $host;

    public function __construct(
        private string $url,
        private string $key,
        private string $service = '',
        private string $environment = '',
        private string $release = '',
        $level = 'debug',
        bool $bubble = true,
        private int $batchSize = 100,
        private float $timeout = 2.0,
    ) {
        parent::__construct($level, $bubble);
        $this->release = $release ?: (string) getenv('DENSIGHT_RELEASE');
        $this->host = (string) gethostname();
    }

    /** Monolog 2 passes an array, Monolog 3 a LogRecord: no type, so both fit. */
    protected function write($record): void
    {
        $r = is_array($record) ? $record : $record->toArray();
        $entry = [
            'timestamp' => $r['datetime'] instanceof \DateTimeInterface
                ? $r['datetime']->format('Y-m-d\TH:i:s.uP') : (string) $r['datetime'],
            'level' => $r['level_name'],
            'logger' => $r['channel'],
            'message' => (string) $r['message'],
            'service' => $this->service,
            'environment' => $this->environment,
            'release' => $this->release,
            'host' => $this->host,
        ];
        $context = array_merge($r['extra'] ?? [], $r['context'] ?? []);
        $exception = $context['exception'] ?? null;
        unset($context['exception']);
        if ($exception instanceof \Throwable) {
            $entry['exception'] = [
                'type' => get_class($exception),
                'value' => $exception->getMessage(),
                'stacktrace' => self::trace($exception),
            ];
        }
        if (PHP_SAPI !== 'cli' && isset($_SERVER['REQUEST_METHOD'])) {
            $entry['method'] = $_SERVER['REQUEST_METHOD'];
            $entry['path'] = $_SERVER['REQUEST_URI'] ?? '';
            $entry['ip'] = $_SERVER['REMOTE_ADDR'] ?? '';
            $entry['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
        }
        foreach ($context as $name => $value) {
            if (!array_key_exists($name, $entry)) {
                $entry[$name] = self::plain($value);
            }
        }
        $this->buffer[] = $entry;
        if (count($this->buffer) >= $this->batchSize) {
            $this->flush();
        }
    }

    public function flush(): void
    {
        if (!$this->buffer) {
            return;
        }
        $body = json_encode($this->buffer, JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE);
        $this->buffer = [];
        $headers = ['Authorization: Bearer ' . $this->key, 'Content-Type: application/json'];
        try {
            if (function_exists('curl_init')) {
                $curl = curl_init($this->url);
                curl_setopt_array($curl, [
                    CURLOPT_POST => true,
                    CURLOPT_POSTFIELDS => $body,
                    CURLOPT_HTTPHEADER => $headers,
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_TIMEOUT_MS => (int) ($this->timeout * 1000),
                    CURLOPT_CONNECTTIMEOUT_MS => (int) ($this->timeout * 1000),
                ]);
                curl_exec($curl);
            } else {
                @file_get_contents($this->url, false, stream_context_create(['http' => [
                    'method' => 'POST', 'header' => implode("\r\n", $headers), 'content' => $body,
                    'timeout' => $this->timeout, 'ignore_errors' => true,
                ]]));
            }
        } catch (\Throwable) {
            // dropped: logging must never break the application
        }
    }

    public function close(): void
    {
        $this->flush();
        parent::close();
    }

    public function reset(): void
    {
        // Long-running workers (queues, Octane) reset handlers between jobs.
        $this->flush();
        parent::reset();
    }

    /** "RuntimeException: boom in /var/www/app/x.php:12\nStack trace:\n#0 ...", with "Caused by" for previous ones. */
    private static function trace(\Throwable $e): string
    {
        $text = '';
        for ($depth = 0; $e && $depth < 5; $e = $e->getPrevious(), $depth++) {
            $text .= ($depth ? "\nCaused by: " : '') . sprintf(
                "%s: %s in %s:%d\nStack trace:\n%s",
                get_class($e), $e->getMessage(), $e->getFile(), $e->getLine(), $e->getTraceAsString()
            );
        }
        return substr($text, 0, 16000);
    }

    private static function plain($value)
    {
        if (is_scalar($value) || $value === null) {
            return $value;
        }
        if (is_array($value)) {
            return array_map([self::class, 'plain'], array_slice($value, 0, 50, true));
        }
        if ($value instanceof \JsonSerializable) {
            return $value->jsonSerialize();
        }
        if ($value instanceof \Stringable) {
            return (string) $value;
        }
        return is_object($value) ? get_class($value) : gettype($value);
    }
}
