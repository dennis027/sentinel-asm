import { Component, OnDestroy, OnInit, computed, inject, input, output, signal } from '@angular/core';
import { LogSource } from '../../../core/models/models';
import { LogService } from '../../../core/services/log.service';
import { OrganizationContextService } from '../../../core/services/organization-context-service';
import { ToastService } from '../../../core/services/toast.service';
import { Icon } from '../../../shared/components/icon/icon';

const POLL_MS = 5000;

interface Step {
  title: string;
  text?: string;
  code?: string;
}

/**
 * What to run on a server to start sending its logs, with its key filled
 * in: Fluent Bit (free, widely used) on Ubuntu/Linux or Windows, a test
 * command, and a live check that turns green when the first logs arrive.
 */
@Component({
  selector: 'app-connect-server',
  imports: [Icon],
  templateUrl: './connect-server.html',
  styleUrl: './connect-server.scss',
})
export class ConnectServer implements OnInit, OnDestroy {
  private readonly logService = inject(LogService);
  private readonly orgContext = inject(OrganizationContextService);
  private readonly toasts = inject(ToastService);
  private pollHandle: ReturnType<typeof setInterval> | undefined;

  // A source fresh from "connect" or "replace key": it carries `key` and `ingest_url`.
  readonly source = input.required<LogSource>();
  readonly done = output<void>();

  readonly status = signal<LogSource['status']>('waiting');
  readonly received = signal(0);

  readonly target = computed(() => {
    const url = new URL(this.source().ingest_url ?? `${location.origin}/api/ingest/`);
    const tls = url.protocol === 'https:';
    return {
      url: url.toString(),
      host: url.hostname,
      port: url.port || (tls ? '443' : '80'),
      path: url.pathname,
      tls: tls ? 'On' : 'Off',
      local: ['localhost', '127.0.0.1'].includes(url.hostname),
      clients: `${url.origin}/api/logs/clients`,
    };
  });

  private readonly output = computed(() => {
    const t = this.target();
    return [
      '[OUTPUT]',
      '    Name        http',
      '    Match       *',
      `    Host        ${t.host}`,
      `    Port        ${t.port}`,
      `    URI         ${t.path}`,
      '    Format      json',
      '    Compress    gzip',
      `    tls         ${t.tls}`,
      `    Header      Authorization Bearer ${this.source().key}`,
    ].join('\n');
  });

  readonly steps = computed<Step[]>(() => {
    switch (this.source().os) {
      case 'windows':
        return this.windowsSteps();
      case 'python':
        return this.pythonSteps();
      case 'node':
        return this.nodeSteps();
      case 'php':
        return this.phpSteps();
      case 'ruby':
        return this.rubySteps();
      case 'go':
        return this.goSteps();
      case 'java':
        return this.javaSteps();
      case 'dotnet':
        return this.dotnetSteps();
      case 'other':
        return this.otherSteps();
      default:
        return this.linuxSteps();
    }
  });

  ngOnInit(): void {
    this.pollHandle = setInterval(() => this.poll(), POLL_MS);
  }

  ngOnDestroy(): void {
    clearInterval(this.pollHandle);
  }

  copy(text: string): void {
    navigator.clipboard
      ?.writeText(text)
      .then(() => this.toasts.success('Copied.'))
      .catch(() => this.toasts.error('Could not copy to the clipboard.'));
  }

  private linuxSteps(): Step[] {
    const key = this.source().key;
    const url = this.target().url;
    return [
      {
        title: 'Install Fluent Bit',
        text: 'The official install script works on Ubuntu, Debian, RHEL, Rocky, Amazon Linux and more.',
        code: 'curl -fsSL https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh | sh',
      },
      {
        title: 'Tell it to send the system journal to Densight',
        text: 'This replaces Fluent Bit\'s default configuration. Sign-ins, sudo, SSH and account changes all go through the journal.',
        code: [
          'sudo mkdir -p /var/lib/fluent-bit',
          "sudo tee /etc/fluent-bit/fluent-bit.conf > /dev/null <<'EOF'",
          '[SERVICE]',
          '    Flush        5',
          '    Log_Level    warn',
          '',
          '[INPUT]',
          '    Name              systemd',
          '    Tag               densight',
          '    Read_From_Tail    On',
          '    DB                /var/lib/fluent-bit/densight.db',
          '',
          this.output(),
          'EOF',
        ].join('\n'),
      },
      {
        title: 'Start it, and keep it running after reboots',
        code: 'sudo systemctl enable --now fluent-bit && sudo systemctl restart fluent-bit',
      },
      {
        title: 'Send a test message (optional)',
        text: 'It shows up straight away; the check below turns green.',
        code:
          `curl -sS -X POST ${url} -H "Authorization: Bearer ${key}" -H "Content-Type: application/json" ` +
          `-d '{"host":"'"$(hostname)"'","program":"densight-test","message":"Hello from '"$(hostname)"'"}'`,
      },
    ];
  }

  private windowsSteps(): Step[] {
    const key = this.source().key;
    const url = this.target().url;
    return [
      {
        title: 'Install Fluent Bit',
        text:
          'Download the Windows installer (64-bit .exe) from fluentbit.io/download and run it with the default ' +
          'options. It installs to C:\\Program Files\\fluent-bit.',
      },
      {
        title: 'Make sure Windows records sign-ins and account changes',
        text: 'In PowerShell, as Administrator. Most servers already do; this makes sure.',
        code: [
          'auditpol /set /subcategory:"Logon" /success:enable /failure:enable',
          'auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable',
          'auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable',
        ].join('\n'),
      },
      {
        title: 'Tell it to send the Security and System logs to Densight',
        code: [
          "@'",
          '[SERVICE]',
          '    Flush        5',
          '    Log_Level    warn',
          '',
          '[INPUT]',
          '    Name          winevtlog',
          '    Channels      Security,System',
          '    Interval_Sec  5',
          '    DB            C:\\ProgramData\\densight-winevtlog.sqlite',
          '',
          this.output(),
          "'@ | Set-Content -Encoding ascii 'C:\\Program Files\\fluent-bit\\conf\\densight.conf'",
        ].join('\n'),
      },
      {
        title: 'Run it as a Windows service',
        text: 'It starts with Windows and runs as Local System, which can read the Security log.',
        code: [
          "New-Service -Name densight-logs -DisplayName 'Densight log shipper' -StartupType Automatic `",
          "  -BinaryPathName '\"C:\\Program Files\\fluent-bit\\bin\\fluent-bit.exe\" -c \"C:\\Program Files\\fluent-bit\\conf\\densight.conf\"'",
          'Start-Service densight-logs',
        ].join('\n'),
      },
      {
        title: 'Send a test message (optional)',
        text: 'It shows up straight away; the check below turns green.',
        code:
          `Invoke-RestMethod -Method Post -Uri ${url} -Headers @{Authorization='Bearer ${key}'} ` +
          "-ContentType 'application/json' -Body (@{host=$env:COMPUTERNAME; program='densight-test'; " +
          'message="Hello from $env:COMPUTERNAME"} | ConvertTo-Json)',
      },
    ];
  }

  private pythonSteps(): Step[] {
    const { key, name } = this.source();
    const { url, clients } = this.target();
    return [
      {
        title: 'Add the Densight handler to your project',
        text:
          'One file, standard library only (Python 3.8+). It sends logs in batches from a background thread, so ' +
          'logging never slows a request, and an outage on our side never breaks your app.',
        code: `curl -fsSLo densight_logging.py ${clients}/densight_logging.py`,
      },
      {
        title: 'Attach it to your logging',
        text: 'Plain Python, Flask or FastAPI: add it to the root logger at start-up. Keep the key in an environment variable.',
        code: [
          'import logging, os',
          'from densight_logging import DensightHandler',
          '',
          'logging.getLogger().addHandler(DensightHandler(',
          `    url="${url}",`,
          `    key=os.environ.get("DENSIGHT_KEY", "${key}"),`,
          `    service="${name}",`,
          '))',
        ].join('\n'),
      },
      {
        title: 'Django: add it to LOGGING in settings.py instead',
        text: 'Unhandled exceptions in views (django.request) arrive with their stack trace and are grouped into errors.',
        code: [
          'LOGGING = {',
          '    "version": 1,',
          '    "disable_existing_loggers": False,',
          '    "handlers": {',
          '        "densight": {',
          '            "class": "densight_logging.DensightHandler",',
          `            "url": "${url}",`,
          `            "key": os.environ.get("DENSIGHT_KEY", "${key}"),`,
          `            "service": "${name}",`,
          '            "level": "INFO",',
          '        },',
          '    },',
          '    "root": {"handlers": ["densight"], "level": "INFO"},',
          '}',
        ].join('\n'),
      },
      {
        title: 'Send a test error (optional)',
        text: 'Logs a real exception with its stack trace; it appears under Errors and the check below turns green.',
        code: [
          "python3 - <<'EOF'",
          'import logging, time',
          'from densight_logging import DensightHandler',
          '',
          `handler = DensightHandler("${url}", "${key}", service="${name}")`,
          'log = logging.getLogger("densight-test")',
          'log.addHandler(handler)',
          'try:',
          '    {}["sku"]',
          'except KeyError:',
          '    log.exception("Test error from Densight setup")',
          'time.sleep(3)  # the handler sends from a background thread',
          'EOF',
        ].join('\n'),
      },
    ];
  }

  private nodeSteps(): Step[] {
    const { key, name } = this.source();
    const { url, clients } = this.target();
    return [
      {
        title: 'Add the Densight logger to your project',
        text: 'One file, no dependencies (Node 18+). It batches logs and sends them in the background.',
        code: `curl -fsSLo densight-logger.js ${clients}/densight-logger.js`,
      },
      {
        title: 'pino (Express, Fastify, Nest with nestjs-pino)',
        text: 'Writes to the console as before and to Densight. Errors logged as { err } keep their stack trace.',
        code: [
          "const pino = require('pino');",
          "const { createDensight } = require('./densight-logger');",
          '',
          'const densight = createDensight({',
          `  url: '${url}',`,
          `  key: process.env.DENSIGHT_KEY || '${key}',`,
          `  service: '${name}',`,
          '});',
          'const logger = pino({}, pino.multistream([{ stream: process.stdout }, { stream: densight.stream }]));',
          '',
          "logger.error({ err: new Error('boom') }, 'Payment failed');",
        ].join('\n'),
      },
      {
        title: 'Or winston',
        code: [
          "const winston = require('winston');",
          "const { createDensight } = require('./densight-logger');",
          '',
          `const densight = createDensight({ url: '${url}', key: process.env.DENSIGHT_KEY || '${key}', service: '${name}' });`,
          'const DensightTransport = densight.WinstonTransport();',
          'const logger = winston.createLogger({',
          '  format: winston.format.combine(winston.format.errors({ stack: true }), winston.format.json()),',
          '  transports: [new winston.transports.Console(), new DensightTransport()],',
          '});',
        ].join('\n'),
      },
      {
        title: 'Send a test error (optional)',
        code:
          `node -e "const d=require('./densight-logger').createDensight({url:'${url}',key:'${key}',service:'${name}'});` +
          `try{null.x}catch(e){d.send({level:'error',message:'Test error from Densight setup',err:{type:e.name,message:e.message,stack:e.stack}})}d.flush()"`,
      },
    ];
  }

  private envSteps(file: string): Step {
    const { key } = this.source();
    const { url } = this.target();
    return {
      title: `Give the app its address and key (${file})`,
      text: 'Keep the key out of your code: it identifies this app to Densight.',
      code: [`DENSIGHT_URL=${url}`, `DENSIGHT_KEY=${key}`].join('\n'),
    };
  }

  private phpSteps(): Step[] {
    const { name } = this.source();
    const { clients } = this.target();
    return [
      {
        title: 'Add the Densight handler to your project',
        text:
          'One file, a Monolog handler (Monolog 2 or 3, PHP 8.0+), so it works with Laravel, Symfony and anything ' +
          'else that uses Monolog. Laravel: app/Logging. Symfony: src/Logging.',
        code: `mkdir -p app/Logging && curl -fsSLo app/Logging/DensightHandler.php ${clients}/DensightHandler.php`,
      },
      this.envSteps('.env'),
      {
        title: 'Laravel: add a channel in config/logging.php',
        text:
          "Then send the default stack to it as well: LOG_STACK=single,densight in .env (Laravel 11), or add " +
          "'densight' to the stack channel's 'channels'. Unhandled exceptions arrive with their stack trace.",
        code: [
          "'densight' => [",
          "    'driver' => 'monolog',",
          "    'handler' => App\\Logging\\DensightHandler::class,",
          "    'with' => [",
          "        'url' => env('DENSIGHT_URL'),",
          "        'key' => env('DENSIGHT_KEY'),",
          `        'service' => '${name}',`,
          "        'release' => env('APP_VERSION', ''),",
          '    ],',
          "    'level' => 'info',",
          '],',
        ].join('\n'),
      },
      {
        title: 'Symfony: register it (config/services.yaml and config/packages/monolog.yaml)',
        code: [
          '# services.yaml',
          'App\\Logging\\DensightHandler:',
          '    arguments:',
          "        $url: '%env(DENSIGHT_URL)%'",
          "        $key: '%env(DENSIGHT_KEY)%'",
          `        $service: '${name}'`,
          '',
          '# monolog.yaml (under when@prod: or the environments you want)',
          'monolog:',
          '    handlers:',
          '        densight:',
          '            type: service',
          '            id: App\\Logging\\DensightHandler',
        ].join('\n'),
      },
      {
        title: 'Send a test error (optional, Laravel)',
        code: `php artisan tinker --execute="Log::channel('densight')->error('Test error from Densight setup', ['exception' => new RuntimeException('Densight test')])"`,
      },
    ];
  }

  private rubySteps(): Step[] {
    const { name } = this.source();
    const { clients } = this.target();
    return [
      {
        title: 'Add the Densight logger to your project',
        text: 'One file, standard library only (Ruby 3.2+). It is a normal Ruby Logger that also sends in the background.',
        code: `curl -fsSLo lib/densight_logger.rb ${clients}/densight_logger.rb`,
      },
      this.envSteps('your environment or .env'),
      {
        title: 'Rails: config/initializers/densight.rb',
        text: 'Keeps writing to the console as before. The error subscriber sends unhandled exceptions with their backtrace (Rails 7.1+).',
        code: [
          'require Rails.root.join("lib/densight_logger")',
          '',
          'Rails.application.configure do',
          '  config.logger = ActiveSupport::TaggedLogging.new(',
          '    Densight::Logger.new(url: ENV.fetch("DENSIGHT_URL"), key: ENV.fetch("DENSIGHT_KEY"),',
          `                         service: "${name}", io: $stdout))`,
          'end',
          'Rails.error.subscribe(Densight::ErrorSubscriber.new(Rails.logger))',
        ].join('\n'),
      },
      {
        title: 'Sinatra, Sidekiq or plain Ruby',
        code: [
          'require_relative "lib/densight_logger"',
          `logger = Densight::Logger.new(url: ENV["DENSIGHT_URL"], key: ENV["DENSIGHT_KEY"], service: "${name}", io: $stdout)`,
          'logger.info("order placed", order_id: 42)',
          'logger.error(exception)   # with its class and backtrace',
        ].join('\n'),
      },
      {
        title: 'Send a test error (optional, Rails)',
        code: `bin/rails runner 'begin; raise "Test error from Densight setup"; rescue => e; Rails.logger.error(e); end; Rails.logger.flush'`,
      },
    ];
  }

  private goSteps(): Step[] {
    const { name } = this.source();
    const { clients } = this.target();
    return [
      {
        title: 'Add the Densight package to your module',
        text: 'One file, standard library only (Go 1.21+): a log/slog handler and HTTP middleware.',
        code: `mkdir -p internal/densight && curl -fsSLo internal/densight/densight.go ${clients}/densight.go`,
      },
      this.envSteps('your environment'),
      {
        title: 'Use it as your logger, and wrap your HTTP handler',
        text:
          'The middleware logs every request (so 5xx bursts, attack probes and password guessing are spotted) and ' +
          'turns a panic into a logged error with its stack. Change the import to your module path.',
        code: [
          'import "example.com/yourapp/internal/densight"',
          '',
          'dh := densight.New(densight.Options{',
          '    URL: os.Getenv("DENSIGHT_URL"), Key: os.Getenv("DENSIGHT_KEY"),',
          `    Service: "${name}", Release: os.Getenv("APP_VERSION"),`,
          '})',
          'defer dh.Close()',
          'logger := slog.New(densight.Tee(slog.NewJSONHandler(os.Stdout, nil), dh))',
          'slog.SetDefault(logger)',
          '',
          'http.ListenAndServe(":8080", densight.Middleware(logger, mux))',
          '',
          '// Errors keep their type: slog.Error("checkout failed", "error", err)',
        ].join('\n'),
      },
    ];
  }

  /** Java and .NET: the app writes JSON lines to a file, Fluent Bit sends them on. */
  private fluentTailSteps(path: string): Step[] {
    return [
      {
        title: 'Install Fluent Bit on the server (or as a sidecar container)',
        text: 'Free and widely used; it follows the log file and sends new lines as they are written.',
        code: 'curl -fsSL https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh | sh',
      },
      {
        title: 'Tell it to send the app\'s log file to Densight',
        code: [
          'sudo mkdir -p /var/lib/fluent-bit',
          "sudo tee /etc/fluent-bit/densight-parsers.conf > /dev/null <<'EOF'",
          '[PARSER]',
          '    Name    densight_json',
          '    Format  json',
          'EOF',
          "sudo tee /etc/fluent-bit/fluent-bit.conf > /dev/null <<'EOF'",
          '[SERVICE]',
          '    Flush         5',
          '    Log_Level     warn',
          '    Parsers_File  densight-parsers.conf',
          '',
          '[INPUT]',
          '    Name     tail',
          `    Path     ${path}`,
          '    Parser   densight_json',
          '    Tag      densight',
          '    DB       /var/lib/fluent-bit/densight-app.db',
          '',
          this.output(),
          'EOF',
          'sudo systemctl enable --now fluent-bit && sudo systemctl restart fluent-bit',
        ].join('\n'),
      },
    ];
  }

  private javaSteps(): Step[] {
    const { name } = this.source();
    const dir = `/var/log/${this.slug(name)}`;
    return [
      {
        title: 'Add the JSON encoder for Logback (Spring Boot uses Logback)',
        text: 'Maven shown; for Gradle: implementation("net.logstash.logback:logstash-logback-encoder:8.0").',
        code: [
          '<dependency>',
          '  <groupId>net.logstash.logback</groupId>',
          '  <artifactId>logstash-logback-encoder</artifactId>',
          '  <version>8.0</version>',
          '</dependency>',
        ].join('\n'),
      },
      {
        title: 'Write JSON logs to a file: src/main/resources/logback-spring.xml',
        text: 'Keeps the usual console output. Exceptions are written with their stack trace, which Densight groups by the method in your code.',
        code: [
          '<configuration>',
          '  <include resource="org/springframework/boot/logging/logback/defaults.xml"/>',
          '  <include resource="org/springframework/boot/logging/logback/console-appender.xml"/>',
          '  <appender name="DENSIGHT" class="ch.qos.logback.core.rolling.RollingFileAppender">',
          `    <file>${dir}/app.json</file>`,
          '    <rollingPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">',
          `      <fileNamePattern>${dir}/app.%d{yyyy-MM-dd}.%i.json.gz</fileNamePattern>`,
          '      <maxFileSize>50MB</maxFileSize>',
          '      <maxHistory>3</maxHistory>',
          '    </rollingPolicy>',
          '    <encoder class="net.logstash.logback.encoder.LogstashEncoder">',
          `      <customFields>{"service":"${name}"}</customFields>`,
          '    </encoder>',
          '  </appender>',
          '  <root level="INFO">',
          '    <appender-ref ref="CONSOLE"/>',
          '    <appender-ref ref="DENSIGHT"/>',
          '  </root>',
          '</configuration>',
        ].join('\n'),
      },
      ...this.fluentTailSteps(`${dir}/app.json`),
      this.tailTest(`${dir}/app.json`, '{"@timestamp":"NOW","level":"ERROR","message":"Test error from Densight setup","logger_name":"densight.Test"}'),
    ];
  }

  private dotnetSteps(): Step[] {
    const { name } = this.source();
    const dir = `/var/log/${this.slug(name)}`;
    return [
      {
        title: 'Add Serilog',
        code: [
          'dotnet add package Serilog.AspNetCore',
          'dotnet add package Serilog.Formatting.Compact',
        ].join('\n'),
      },
      {
        title: 'Write compact JSON logs to a file: Program.cs',
        text:
          'UseSerilogRequestLogging writes one line per request (method, path, status), so 5xx bursts and attack ' +
          'probes are spotted. Exceptions keep their stack trace.',
        code: [
          'using Serilog;',
          'using Serilog.Formatting.Compact;',
          '',
          'builder.Host.UseSerilog((context, config) => config',
          '    .ReadFrom.Configuration(context.Configuration)',
          '    .Enrich.FromLogContext()',
          `    .Enrich.WithProperty("service", "${name}")`,
          '    .WriteTo.Console()',
          `    .WriteTo.File(new CompactJsonFormatter(), "${dir}/app.clef", rollingInterval: RollingInterval.Day,`,
          '                  retainedFileCountLimit: 3));',
          '',
          '// after var app = builder.Build();',
          'app.UseSerilogRequestLogging();',
        ].join('\n'),
      },
      ...this.fluentTailSteps(`${dir}/app*.clef`),
      this.tailTest(`${dir}/app-test.clef`, '{"@t":"NOW","@l":"Error","@mt":"Test error from Densight setup"}'),
    ];
  }

  private tailTest(file: string, line: string): Step {
    return {
      title: 'Send a test line (optional)',
      text: 'Appends one line the way the app would; it shows up within a few seconds.',
      code: `echo '${line}' | sed "s/NOW/$(date -u +%Y-%m-%dT%H:%M:%SZ)/" | sudo tee -a ${file} > /dev/null`,
    };
  }

  private slug(name: string): string {
    return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'app';
  }

  private otherSteps(): Step[] {
    const { key, name } = this.source();
    const url = this.target().url;
    return [
      {
        title: 'Post your logs as JSON',
        text:
          'Send a JSON array (or one object per line) to the address below with the key as a Bearer token; gzip ' +
          'is fine. Fluent Bit, Vector, Logstash and most logging libraries\' HTTP outputs can do this.',
        code: [`POST ${url}`, `Authorization: Bearer ${key}`, 'Content-Type: application/json'].join('\n'),
      },
      {
        title: 'Use these field names where you can',
        text:
          'message and level are enough. Add error.type and error.stack for exceptions (grouped into errors), and ' +
          'method, path, status and ip for web requests (to spot 5xx spikes, attack probes and password guessing).',
        code: JSON.stringify(
          [
            { timestamp: '2026-01-01T12:00:00Z', level: 'error', service: name, message: 'Payment failed',
              error: { type: 'TimeoutError', message: 'gateway timed out', stack: 'TimeoutError: ...' } },
            { level: 'info', service: name, method: 'POST', path: '/login', status: 401, ip: '203.0.113.7', user: 'alice' },
          ],
          null,
          2,
        ),
      },
      {
        title: 'Send a test message (optional)',
        code:
          `curl -sS -X POST ${url} -H "Authorization: Bearer ${key}" -H "Content-Type: application/json" ` +
          `-d '{"service":"${name}","level":"error","message":"Test error from Densight setup"}'`,
      },
    ];
  }

  private poll(): void {
    const org = this.orgContext.selectedOrganization();
    if (!org) return;
    this.logService.sources(org.id).subscribe({
      next: (sources) => {
        const mine = sources.find((s) => s.id === this.source().id);
        if (!mine) return;
        this.received.set(mine.events_received);
        if (mine.status === 'receiving' && this.status() !== 'receiving') {
          this.toasts.success(`${mine.name} is sending logs.`);
        }
        this.status.set(mine.status);
      },
      error: () => undefined,
    });
  }
}
