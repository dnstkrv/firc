<script lang="ts">
  import { Popover, RadioGroup } from "bits-ui";

  import { t } from "../../../data/locale.svelte";

  import { SelectOpen, X } from "../../../components/ui/icons";
  import {
    isValidPorts,
    joinPorts,
    PORTS_MAX_SLOTS,
    portsSlots,
    portToken,
    splitPorts,
    type PortProblem,
  } from "../../../utils/rule-validators";

  type Proto = "tcp" | "udp" | undefined;

  let {
    proto,
    ports,
    invalid = false,
    onchange,
  }: {
    proto: Proto;
    ports: string | undefined;
    invalid?: boolean;
    onchange: (proto: Proto, ports: string | undefined) => void;
  } = $props();

  let open = $state(false);
  let draft = $state("");
  let problem = $state<PortProblem | "limit" | undefined>();
  let input = $state<HTMLInputElement>();
  let original: { proto: Proto; ports: string | undefined } = {
    proto: undefined,
    ports: undefined,
  };
  const id = $props.id();

  const tokens = $derived(ports ? ports.split(",") : []);
  const shown = (token: string) => token.replace("-", "–");
  const protoLabel = $derived(proto ? proto.toUpperCase() : t("any protocol"));
  const summary = $derived(
    tokens.length > 0
      ? `${protoLabel} · ${tokens.map(shown).join(", ")}`
      : proto
        ? `${protoLabel} · ${t("all ports")}`
        : protoLabel,
  );
  const reason = $derived(
    problem === "range"
      ? t("A port is 1 to 65535")
      : problem === "order"
        ? t("A range goes from the lower port up")
        : problem === "syntax"
          ? t("A port or a range like 1000-2000")
          : problem === "limit"
            ? t("No more than {max} ports").replace("{max}", String(PORTS_MAX_SLOTS))
            : "",
  );
  const choices: { value: string; label: string }[] = $derived([
    { value: "any", label: t("Any") },
    { value: "tcp", label: "TCP" },
    { value: "udp", label: "UDP" },
  ]);

  function setProto(value: string) {
    const next: Proto = value === "tcp" || value === "udp" ? value : undefined;
    draft = "";
    problem = undefined;
    onchange(next, next ? ports : undefined);
  }

  function add(text: string): boolean {
    const pieces = splitPorts(text).filter(
      (p, i, all) => !tokens.includes(p) && all.indexOf(p) === i,
    );
    for (const piece of pieces) {
      const parsed = portToken(piece);
      if ("problem" in parsed) {
        problem = parsed.problem;
        return false;
      }
    }
    const next = [...tokens, ...pieces];
    if (portsSlots(next) > PORTS_MAX_SLOTS) {
      problem = "limit";
      return false;
    }
    problem = undefined;
    if (pieces.length > 0) onchange(proto, joinPorts(next));
    return true;
  }

  function remove(index: number) {
    problem = undefined;
    const next = tokens.filter((_, i) => i !== index);
    onchange(proto, next.length > 0 ? joinPorts(next) : undefined);
    input?.focus();
  }

  function onInput(event: Event & { currentTarget: HTMLInputElement }) {
    const value = event.currentTarget.value;
    const cut = value.lastIndexOf(",");
    if (cut !== -1 && add(value.slice(0, cut))) {
      draft = value.slice(cut + 1);
      event.currentTarget.value = draft;
      return;
    }
    draft = value;
    if (cut === -1) problem = undefined;
  }

  function onKeydown(event: KeyboardEvent) {
    if (event.isComposing) return;
    if (event.key === "Enter") {
      event.preventDefault();
      commit();
    } else if (event.key === "Backspace" && draft === "" && tokens.length > 0) {
      event.preventDefault();
      remove(tokens.length - 1);
    }
  }

  function commit() {
    if (draft.trim() !== "" && add(draft)) draft = "";
  }

  function keep() {
    commit();
    if (draft.trim() === "") return;
    const pieces = splitPorts(draft).filter((p) => !tokens.includes(p));
    draft = "";
    if (pieces.length > 0) onchange(proto, joinPorts([...tokens, ...pieces]));
  }

  function restore() {
    draft = "";
    problem = undefined;
    if (proto !== original.proto || ports !== original.ports) {
      onchange(original.proto, original.ports);
    }
  }

  function onOpenChange(next: boolean) {
    if (next) original = { proto, ports };
    else keep();
    draft = "";
    problem = undefined;
  }
</script>

<Popover.Root bind:open {onOpenChange}>
  <Popover.Trigger
    class={invalid ? "rule-ports invalid" : "rule-ports"}
    aria-label={summary}
    title={summary}
    aria-invalid={invalid}
  >
    <span class="rule-ports-summary">{summary}</span>
    <SelectOpen size={14} />
  </Popover.Trigger>
  <Popover.Portal>
    <Popover.Content
      class="rule-ports-editor"
      side="bottom"
      align="start"
      sideOffset={6}
      collisionPadding={8}
      onEscapeKeydown={restore}
      onOpenAutoFocus={(event) => {
        if (!input) return;
        event.preventDefault();
        input.focus();
      }}
    >
      <RadioGroup.Root
        class="rule-ports-protos"
        orientation="horizontal"
        aria-label={t("Protocol")}
        value={proto ?? "any"}
        onValueChange={setProto}
      >
        {#each choices as choice (choice.value)}
          <RadioGroup.Item class="rule-ports-proto" value={choice.value}>
            {choice.label}
          </RadioGroup.Item>
        {/each}
      </RadioGroup.Root>
      {#if proto}
        <label class="rule-ports-label" for="{id}-input">{t("Ports")}</label>
        <div class="rule-ports-tokens" class:invalid={problem !== undefined}>
          {#each tokens as token, i (i)}
            <span class="port-token" class:invalid={!isValidPorts(token)}>
              {shown(token)}
              <button
                type="button"
                aria-label={`${t("Remove")} ${shown(token)}`}
                onclick={() => remove(i)}
              >
                <X size={12} />
              </button>
            </span>
          {/each}
          <input
            id="{id}-input"
            type="text"
            enterkeyhint="done"
            autocomplete="off"
            placeholder={t("another port or 1000-2000")}
            aria-describedby="{id}-hint"
            bind:this={input}
            value={draft}
            oninput={onInput}
            onkeydown={onKeydown}
            onblur={keep}
          />
        </div>
        {#if problem}
          <div class="rule-ports-error" role="status">{reason}</div>
        {/if}
        <div class="rule-ports-hint" id="{id}-hint">
          {t(
            "Empty means all ports. Up to {max} ports, a range counts as two. Enter or a comma adds one.",
          ).replace("{max}", String(PORTS_MAX_SLOTS))}
        </div>
      {/if}
    </Popover.Content>
  </Popover.Portal>
</Popover.Root>

<style>
  :global(.rule-ports) {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    flex: 0 1 auto;
    min-width: 0;
    max-width: 100%;
    padding: 0.2rem 0.5rem;
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.4rem;
    background: transparent;
    color: var(--text-2);
    font-family: var(--font);
    font-size: 0.9rem;
    cursor: pointer;
  }

  :global(.rule-ports:hover),
  :global(.rule-ports:focus-visible),
  :global(.rule-ports[data-state="open"]) {
    color: var(--text);
    background-color: var(--bg-light);
  }

  :global(.rule-ports.invalid) {
    border-color: var(--red);
  }

  .rule-ports-summary {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  :global(.rule-ports-editor) {
    display: flex;
    flex-direction: column;
    gap: 0.45rem;
    width: 19rem;
    max-width: calc(100vw - 1rem);
    box-sizing: border-box;
    padding: 0.5rem;
    background-color: var(--bg-dark-extra);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    box-shadow: var(--shadow-popover);
    color: var(--text);
    z-index: 30;
    outline: none;
  }

  :global(.rule-ports-protos) {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 0.2rem;
    padding: 0.2rem;
    border-radius: 0.4rem;
    background: var(--bg-light);
  }

  :global(.rule-ports-proto) {
    padding: 0.25rem 0;
    border: none;
    border-radius: 0.3rem;
    background: transparent;
    color: var(--text-2);
    font-family: var(--font);
    font-size: 0.9rem;
    cursor: pointer;
  }

  :global(.rule-ports-proto[data-state="checked"]) {
    background: var(--bg-light-extra);
    color: var(--text);
  }

  .rule-ports-label {
    color: var(--text-2);
    font-size: 0.8rem;
  }

  .rule-ports-tokens {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.3rem;
    padding: 0.3rem;
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.4rem;
    background: var(--bg-light);
  }

  .rule-ports-tokens:focus-within {
    border-color: var(--accent);
  }

  .rule-ports-tokens.invalid {
    border-color: var(--red);
  }

  .port-token {
    display: inline-flex;
    align-items: center;
    gap: 0.15rem;
    padding: 0.05rem 0.2rem 0.05rem 0.4rem;
    border-radius: 0.3rem;
    background: color-mix(in oklab, var(--accent) 22%, transparent);
    font-size: 0.85rem;
  }

  .port-token.invalid {
    background: color-mix(in oklab, var(--red) 30%, transparent);
  }

  .port-token button {
    display: inline-flex;
    padding: 0;
    border: none;
    background: transparent;
    color: var(--text-2);
    cursor: pointer;
  }

  .rule-ports-tokens input {
    flex: 1 1 8rem;
    min-width: 0;
    padding: 0.1rem 0.2rem;
    border: none;
    background: transparent;
    color: var(--text);
    font-family: var(--font);
    font-size: 0.9rem;
    outline: none;
  }

  .rule-ports-error {
    color: var(--red);
    font-size: 0.75rem;
  }

  .rule-ports-hint {
    color: var(--text-2);
    font-size: 0.75rem;
  }
</style>
