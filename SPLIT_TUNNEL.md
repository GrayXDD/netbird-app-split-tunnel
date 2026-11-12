# NetBird fork: per-app split tunneling

Форк [netbirdio/netbird](https://github.com/netbirdio/netbird) с **туннелированием по приложениям в самом клиенте** (v1, Windows): выбранные приложения ходят через NetBird (например, через exit node), остальные — напрямую с родного IP. Без драйверов, без сторонних движков.

## Как пользоваться

- **UI:** главный экран → **«Туннелирование приложений»** (строка внизу простого вида / вкладка «Приложения» в расширенном):
  - тумблер вкл/выкл в заголовке (список и режим переживают выключение); режим: «Через NetBird только выбранные» (include) / «всё, кроме выбранных» (exclude);
  - добавление: кнопка **«+»** открывает диалог выбора exe (как в Amnezia), поле поиска даёт подсказки по запущенным процессам;
  - «Применить» — настройки применяются к живому подключению (при включённом демоне — на лету, без рестарта).
- **CLI:** `netbird apps add opera.exe telegram.exe` / `apps remove` / `apps list` / `apps mode include|exclude|off`.
- **ENV-override** (для тестов): `NB_SPLIT_TUNNEL=include:opera.exe,telegram.exe` — приоритетнее файла настроек (`%PROGRAMDATA%\Netbird\split.json`).

Установщик — в [Releases](../../releases). Ставится поверх обычного NetBird с сохранением настроек; возврат на сток — официальным установщиком.

## Как это устроено (архитектура)

Весь трафик, как обычно, затягивается в туннель маршрутами exit-node. Решение принимается на пути пакета в туннель:

1. **Точка решения** — `client/firewall/uspfilter/filterOutbound` (userspace-файрвол клиента): после DNS-хуков, до conntrack. На каждый **новый** поток (TCP SYN / новый UDP 4-tuple).
2. **Атрибуция** — `client/internal/split`: снимки таблиц сокетов и процессов (gopsutil, `GetExtendedTcpTable`) → PID → basename exe. Кеш вердиктов с TTL; **промах атрибуции = туннель (fail-closed)**.
3. **Вердикты:**
   - *tunnel* — пакет идёт в WireGuard как обычно (также: любые адреса сетей NetBird и сетевых роутов, DNS, ICMP, фрагменты, IPv6);
   - *bypass* — пакет инжектится в отдельный gVisor-стек `client/firewall/uspfilter/bypass`: TCP терминируется в userspace и переизлучается сокетом, привязанным к **физическому интерфейсу** (`IP_UNICAST_IF`, готовый механизм самоисключения самого демона) — петли маршрутов нет. Ответы пишутся в raw TUN обратно хосту.
4. **Настройки** — RPC `Get/SetSplitTunnel` демона (права не нужны: пишет daemon), hot-apply через `Engine.ApplySplitTunnelNow`.

Ключевые пакеты: `client/internal/split`, `client/firewall/uspfilter/bypass`, `client/firewall/uspfilter/split.go`, `client/internal/split_wiring.go`, `client/ui/services/split_tunnel.go`, раздел `client/ui/frontend/src/modules/split/` (главный экран).

## Ограничения v1

- Windows only (на других ОС включение возвращает честную ошибку).
- IPv4 only (IPv6 всегда идёт в туннель); фрагменты и ICMP — в туннель.
- Атрибуция по basename exe (все копии одного имени идут одинаково).
- DNS резолвится общим резолвером демона (имена видит родной аплинк).
- Требуется advanced routing (дефолт на Windows); в legacy/netstack-режимах включение отказывается с ошибкой.

## Сборка из исходников

```bash
# демон + CLI
go build -trimpath -ldflags "-s -w -X github.com/netbirdio/netbird/version.version=0.82.1-appsplit" -o build/netbird.exe ./client

# UI (нужны wails3 CLI и pnpm)
cd client/ui && wails3 generate bindings -clean=true -ts
cd frontend && pnpm install && pnpm run build
cd .. && go build -tags production -trimpath -ldflags="-w -s -H windowsgui" -o build/netbird-ui.exe .

# установщик (NSIS 3.10 + плагины EnVar/ShellExecAsUser, стейджинг в dist/netbird_windows_amd64/)
cd client && APPVER=0.82.2.3 makensis /DARCH=amd64 installer.nsis
```

## Коммиты фичи

Ветка `app-split-tunnel`. Ядро, RPC/hot-apply и UI — отдельными атомарными коммитами (см. `git log` ветки).

## Лицензия

BSD-3-Clause (как upstream netbird). Основан на [netbirdio/netbird](https://github.com/netbirdio/netbird); gVisor-стек переиспользует паттерны `uspfilter/forwarder` самого NetBird.
