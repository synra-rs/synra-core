synra:plugin@1.0.0
world plugin
import host (36 function(s))
export lifecycle (4 function(s))
export share (2 function(s))
export actions (1 function(s))
29 gated function(s), 7 ungated, 25 distinct capabilit(ies)

ungated:
  env-sdk-version: reads a fact about the environment
  env-host-kind: reads a fact about the environment
  env-locale: reads a fact about the environment
  env-dark-mode: reads a fact about the environment
  env-can: reads a fact about the environment
  platform-capabilities: reads a fact about the environment
  plugin-id: reads a fact about the environment

gated:
  action-declare: action:declare
  action-invoke: action:invoke:*
  action-list: action:list
  device-broadcast: device:broadcast
  device-list: device:list
  device-send: device:send:*
  event-emit: event:emit:*
  event-subscribe: event:subscribe:*
  log: log:*
  network-fetch: network:fetch:*
  network-websocket: network:websocket:*
  platform-notify: platform:notify
  platform-open-path: platform:open-path
  platform-open-url: platform:open-url
  platform-read-clipboard: platform:read-clipboard
  platform-reveal-path: platform:reveal-path
  platform-simulate-keys: platform:simulate-keys
  platform-write-clipboard: platform:write-clipboard
  plugin-clear-data: plugin:data:clear
  secret-delete: storage:secure:write
  secret-get: storage:secure:read
  secret-set: storage:secure:write
  storage-delete: storage:local:write
  storage-get: storage:local:read
  storage-keys: storage:local:read
  storage-quota: storage:local:read
  storage-set: storage:local:write
  transfer-send: file:transfer:send
  transfer-status: file:transfer:read

capabilities:
  action:declare
  action:invoke:*
  action:list
  device:broadcast
  device:list
  device:send:*
  event:emit:*
  event:subscribe:*
  file:transfer:read
  file:transfer:send
  log:*
  network:fetch:*
  network:websocket:*
  platform:notify
  platform:open-path
  platform:open-url
  platform:read-clipboard
  platform:reveal-path
  platform:simulate-keys
  platform:write-clipboard
  plugin:data:clear
  storage:local:read
  storage:local:write
  storage:secure:read
  storage:secure:write
