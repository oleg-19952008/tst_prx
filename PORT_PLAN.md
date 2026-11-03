# План порта TG WS Proxy на .NET 9 (Windows, консольное приложение)

> Источник: `tg-ws-proxy-main_py` (Python ≥3.8, asyncio + CustomTkinter GUI).
> Цель: перенести ядро MTProto-WS-прокси на **C# / .NET 9**, только **Windows**,
> **консольное приложение**, настройки — в **файл конфигурации**.
> Тесты (`tests/`) и GUI (`ui/`, трей, автообновление) **не переносятся**.

---

## 0. Область переноса

### Переносимые модули Python → компоненты C#

| Python (`proxy/`, `utils/`) | Назначение | C#-аналог |
|---|---|---|
| `tg_ws_proxy.py` | Точка входа сервера, запуск bridge/pool | `Program.cs` + `ProxyHost` (BackgroundService) |
| `bridge.py` | Мост клиент↔Telegram (MTProto obfuscated2, handshake) | `BridgeHandler` |
| `balancer.py` | Балансировка между IP датацентров Telegram | `DcBalancer` |
| `pool.py` | Пул соединений к DC | `ConnectionPool` |
| `raw_websocket.py` | Raw WebSocket-клиент (wss к прокси-эндпоинтам) | `RawWebSocketClient` (на `System.Net.WebSockets.ClientWebSocket` или свой фреймовый парсер поверх `SslStream`) |
| `h2_transport.py`, `cf_h2.py` | HTTP/2-транспорт (Cloudflare), frame-level | Собственный минимальный H2-фрейм-кодек поверх `SslStream` (ALPN `h2`) — см. риски |
| `fake_tls.py` | Полноценный мини-TLS-стек серверной стороны: `verify_client_hello`, `parse_client_hello` (cipher suites / key_share), подбор suite, X25519 key_share, `build_server_hello`, обёртка TLS-записей (`wrap_tls_record`), потоковый читатель TLS-рекордов, профилирование длины первого appdata (`probe_appdata_len`) | `FakeTls` — байт-в-байт порт структур и таблиц; тот же набор функций в `Transport/FakeTls/` |
| `_aes.py` | AES-CTR/IGE шифрование MTProto | `System.Security.Cryptography.Aes` + ручной CTR-режим (или `Aes.Create()` с переносом счётчика) |
| `config.py` | Структура настроек, валидация | `ProxyConfig` (POCO) + Microsoft.Extensions.Configuration |
| `stats.py` | Статистика соединений/трафика | `ProxyStats` (Interlocked/`Stopwatch`) |
| `network_debug.py` | Отладочный вывод сети | Флаги в конфиге + `ILogger` (Debug level) |
| `event_loop.py` | Настройка asyncio event loop | Не нужен (TPL/Kestrel-подобный сокетный цикл) |
| `utils/utils.py` | Мелкие хелперы (IP, парсинг, таймеры) | `Core/Utils` |
| `utils/default_config.py` | Дефолты | `appsettings.json` + `ProxyConfig.Defaults` |
| `utils/logging_setup.py` | Настройка логов | `Microsoft.Extensions.Logging` + Serilog/NConsole (консольный форматтер) |

### Не переносим
- `ui/` (CustomTkinter), `tray_common.py`, `win32_theme.py` — GUI/трей отбрасываем;
- `windows.py`, `linux.py`, `macos.py`, `packaging/`, `Dockerfile` — замена на `dotnet publish`;
- `utils/*_update.py`, `update_check.py` — автотест апдейтов не нужен;
- `diagnostics.py` — по желанию: урезать до консольной команды `--diagnostics`;
- `tests/` — по требованию не переносим.

---

## 1. Каркас решения

```
TgWsProxy.Net/
├── TgWsProxy.sln
├── src/TgWsProxy/
│   ├── Program.cs               // Host.CreateApplicationBuilder + ConsoleLifetime
│   ├── appsettings.json         // основные настройки
│   ├── Core/                    // BridgeHandler, DcBalancer, ConnectionPool
│   ├── Crypto/                  // MtprotoAes, ObfuscationKeys, FakeTls
│   ├── Transport/               // RawWebSocketClient, Http2Transport, CfH2
│   ├── Configuration/           // ProxyConfig, валидация
│   └── Observability/           // StatsCounter, NetworkDebug
└── docs/                        // миграция ключевых md-заметок (опционально)
```

Параметры csproj:
- `net9.0-windows`, `<Nullable>enable</Nullable>`, `<ImplicitUsings>enable</ImplicitUsings>`;
- `<PublishSingleFile>true</PublishSingleFile>`, `<SelfContained>true</SelfContained>`,
  `<RuntimeIdentifier>win-x64</RuntimeIdentifier>`, `<EnableCompressionInSingleFile>true</EnableCompressionInSingleFile>`;
- NuGet: `Microsoft.Extensions.Hosting`, `Microsoft.Extensions.Configuration.Json`,
  `Microsoft.Extensions.Logging.Console` (+ при желании `Serilog.Extensions.Hosting`).

Контракты CLI:
- `TgWsProxy.exe` — запуск с `appsettings.json` рядом с exe (переопределение через `--config <path>`);
- `--version`, `--diagnostics` (опционально), `Ctrl+C` — graceful shutdown через `IHostApplicationLifetime`.

---

## 2. Конфигурация (из UI-настроек Python → appsettings.json)

Реальные поля `proxy/config.py::ProxyConfig` (дефолты из исходников) → схема `appsettings.json`:

| Python-поле | Дефолт | JSON-ключ | Примечание |
|---|---|---|---|
| `port` | `1443` | `Proxy:Port` | |
| `host` | `'127.0.0.1'` | `Proxy:Host` | |
| `secret` | `os.urandom(16).hex()` | `Proxy:Secret` | hex obfuscated2-секрета; если пусто — генерировать на старте и печатать в консоль |
| `dc_redirects` | `{2: '149.154.167.220', 4: '149.154.167.220'}` | `Proxy:DcRedirects` | словарь `"<dc>": "<ip>"` (в tray-конфиге формат `"2:149.154.167.220"`) |
| `buffer_size` | `256*1024` | `Proxy:BufferSizeKb` | в UI задаётся в КБ (`buf_kb`) |
| `pool_size` | `4` | `Proxy:PoolSize` | |
| `fallback_cfproxy` | `True` | `Proxy:FallbackCfProxy` | |
| `cfproxy_user_domains` | `[]` | `Proxy:CfProxyUserDomains` | |
| `cfproxy_worker_domains` | `[]` | `Proxy:CfProxyWorkerDomains` | |
| `cfproxy_h2_media` | `True` | `Proxy:CfProxyH2Media` | вместе с FallbackCfProxy&&!DisableSecure&&!ForceTestDC даёт свойство `H2Enabled` |
| `disable_secure` | `False` | `Proxy:DisableSecure` | |
| `fake_tls_domain` | `''` | `Proxy:FakeTlsDomain` | |
| `proxy_protocol` | `False` | `Proxy:ProxyProtocol` | |
| `force_test_dc` | `False` | `Proxy:ForceTestDc` | |

Пример файла:

```json
{
  "Proxy": {
    "Port": 1443,
    "Host": "127.0.0.1",
    "Secret": "",
    "DcRedirects": { "2": "149.154.167.220", "4": "149.154.167.220" },
    "BufferSizeKb": 256,
    "PoolSize": 4,
    "FallbackCfProxy": true,
    "CfProxyUserDomains": [],
    "CfProxyWorkerDomains": [],
    "CfProxyH2Media": true,
    "DisableSecure": false,
    "FakeTlsDomain": "",
    "ProxyProtocol": false,
    "ForceTestDc": false
  },
  "Logging": { "LogLevel": { "Default": "Information" } }
}
```

Отбрасываемые настройки tray-конфига (`utils/default_config.py`): `verbose` → уровень логирования, `check_updates`, `appearance`, `language`, `autostart`, `log_max_mb` (GUI/трей-специфика).

Этапы:
1. Реализовать загрузку по таблице выше; отдельно портировать декодер CFPROXY-доменов (`_CFPROXY_ENC` + Caesar-шифр `_dd`, суффикс `.co.uk`) и загрузчик `CFPROXY_DOMAINS_URL` (GitHub raw, список доменов).
2. Bind через `IOptions<ProxyConfig>`; вычисляемое свойство `H2Enabled` воспроизвести как `bool H2Enabled => ...`.
3. Валидация-at-startup (`IValidateOptions<T>`): порт 1–65535, secret — 32 hex-символа, DC-IP резолвятся, непротиворечивость флагов H2.
4. Секрет-по-умолчанию: генерация 16 случайных байт (`RandomNumberGenerator`) и вывод в консоль при пустом значении (Telegram Desktop нужно переподключать вручную — аналог генерации в GUI).

---

## 3. Ядро протокола (порядок работ)

### Фаза A — криптография и обфускация (без сети, проверяется векторами из Python)
1. **AES**: реализовать CTR-режим для MTProto (`_aes.py`): префикс nonce+counter, инкремент 128-битного счётчика big-endian. Базис — `Aes.EncryptCbc` над обнулённым IV как keystream либо ручной XOR keystream.
2. **Obfuscated2**: генерация ephemeral-пар (X25519 — `System.Security.Cryptography.ECDiffieHellman` с `named curve X25519`, доступен в .NET 8+), derived keys (SHA256), запись/чтение первых 64 байт handshake.
3. **FakeTLS** (`fake_tls.py`): портировать серверную часть мини-TLS: `verify_client_hello` (проверка obfs-тега в ClientHello по секрету), `parse_client_hello` (cipher suites, key_share groups), `_select_cipher_suite`, `_server_key_share` (X25519), `build_server_hello`, `wrap_tls_record` и TLS-record-читатель; отдельно — профилирование длины первого appdata (`probe_appdata_len` / `set_profiled_appdata_len`). Побайтная сверка с Python-генератором (golden files).

### Фаза B — транспорт
4. **RawWebSocketClient**: кадры permessage-deflate НЕ используются — проверить; если да, использовать `ClientWebSocket` c `NoDelay`; иначе собственный парсер поверх `SslStream` (нужно для FakeTLS-рукопожатия, т.к. стандартный стек не даст подменить ClientHello).
5. **HTTP/2-транспорт** (`h2_transport.py`, `cf_h2.py`): минимальный фрейм-кодек (SETTINGS/HEADERS(HPACK)/DATA/PING/WINDOW_UPDATE), ALPN `h2` через `SslStream.AuthenticateAsClientAsync(ApplicationProtocols: ["h2"])`. Это самая трудоёмкая часть — см. риски.

### Фаза C — мост и балансировка
6. **BridgeHandler**: accept локального сокета (TcpListener), чтение obfuscated2-заголовка клиента, определение режима (WS/H2/direct), сплайсинг двух потоков с `Stream.CopyToAsync` в обе стороны + корректный shutdown обеих сторон.
7. **ConnectionPool + DcBalancer**: переиспользование WS-сессий к IP датацентров (списки DC берём из констант Python-версии), health-check, ротация при таймаутах, fallback на прямой TCP при `FallbackToDirect=true`.
8. **StatsCounter / NetworkDebug**: счётчики подключений, байт, ошибок; периодический вывод в консоль (замена окон дашборда GUI).

### Фаза D — консольное приложение
9. `Program.cs`: Host + Kestrel-не-нужен; сервис `ProxyServer : BackgroundService` слушает `ListenAddress:Port`; логирование старта (адрес, режим, версия); обработка `SIGINT/Ctrl+C`, `SocketException`,Culture-neutral вывод.
10. Окно консоли: заменить функции GUI-статуса на печатаемый блок (порт, активные соединения, выбор DC). Трей и тема Windows — вырезаны.

---

## 4. Сборка и доставка (Windows)

- `dotnet publish -c Release -r win-x64 --self-contained -p:PublishSingleFile=true`
- Артефакт: один `TgWsProxy.exe` + `appsettings.json` (+ `LICENSE`).
- Опционально: `dotnet format`, `Analyzers` (`Microsoft.CodeAnalysis.NetAnalyzers`), trim-incompatible предупреждения не критичны.
- GitHub Actions workflow: windows-latest, артефакт zip (замена PyInstaller/packaging).

---

## 5. Риски и особенности

| Риск | Комментарий / митигция |
|---|---|
| **FakeTLS поверх стандартного SslStream невозможен** | `SslStream` (SChannel) не даёт подменить ClientHello. Решение: собственная реализация TLS-записи поверх raw-сокета для handshake (как в Python — там тоже самописный пакет), затем переход на AES-WS-framing. Обязательный spike в первую очередь. |
| **HTTP/2 без библиотек** | `System.Net.Http` умеет H2, но не даёт низкоуровневый контроль (priority, window, сырые frames для cf_h2). Порт собственного кодека; объём ~1–2 недели. |
| **X25519/производные ключи** | API есть (`ECDiffieHellman.Create(EccNamedAlgorithm.X25519)`), но нужно аккуратно воспроизвести порядок байтов и HKDF-эквиваленты Python. Сверка golden vectors. |
| **Производительность asyncio vs TPL** | Для десятков–сотен соединений TPL достаточно; следить за `Memory<byte>`/ArrayPool, избегать копий буферов в сплайсинге. |
| **Периодические обновления upstream Python** | Зафиксировать версию источника в `docs/SOURCE_VERSION.md`; диффы протокола редки, но важны (DC-списки, дефолты). |

---

## 6. Порядок выполнения (чек-лист)

- [ ] 1. Скелет решения + CI-сборка win-x64 (пустой exe с `--version`).
- [ ] 2. Карта конфигурации Python→JSON, `ProxyConfig` + валидация.
- [ ] 3. AES-CTR + obfuscated2 + X25519 (проверка golden vectors из Python).
- [ ] 4. FakeTLS-генератор (побайтовая сверка с Python).
- [ ] 5. Spike: raw WS поверх SslStream/self-TLS против реального эндпоинта.
- [ ] 6. H2-транспорт (frames, HPACK, ping/keepalive).
- [ ] 7. Bridge + Pool + Balancer + fallback direct.
- [ ] 8. Stats/network-debug вывод в консоль.
- [ ] 9. Program.cs/Hosting, Ctrl+C shutdown, `--config`.
- [ ] 10. Ручное E2E: Telegram Desktop → 127.0.0.1:port → сравнение поведения с Python-версией (latency, стабильность, логи).
- [ ] 11. Документация: README.NET.md (запуск, конфиг, отличия от GUI-версии).

Оценка: ядро (пп. 3–7) — основная сложность; суммарно ориентировочно 4–6 недель работы одного разработчика.
