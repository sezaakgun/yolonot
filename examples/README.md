# Example configurations

Copy a selected example to `~/.yolonot/config.json`, adjust its endpoints and
model IDs, then run `yolonot config validate` and `yolonot effective --harness
<name>`. Back up existing configuration before replacing it.

- `local-only.json`: fast-allow parser only, learning disabled. Commands that
  it cannot approve fall through to the host's native policy; this is not a
  complete command classifier.
- `local-typed.json`: fast-allow followed by a loopback System One endpoint.
  Start your compatible local model server separately.
- `strict.json`: strict risk profile, explicit failure handling and a chat
  model. Supply the configured API-key variable to the process running the
  hook/mod; a terminal export may not reach a desktop host. Adjust the model
  to one your account can access. See [desktop credentials](../docs/configuration.md#credentials-in-desktop-hosts).

See [configuration](../docs/configuration.md), the
[editor schema](../docs/config.schema.json) and the
[harness verification matrix](../docs/harnesses.md).
