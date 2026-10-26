<script lang="ts">
  import { Popover } from "bits-ui";

  import Tooltip from "../../../components/ui/Tooltip.svelte";
  import { t } from "../../../data/locale.svelte";

  import { Comment } from "../../../components/ui/icons";
  import {
    cleanComment,
    COMMENT_MAX_BYTES,
    cutToBytes,
    utf8Length,
  } from "../../../utils/rule-comment";

  let {
    comment,
    matched = false,
    onchange,
  }: {
    comment: string | undefined;
    matched?: boolean;
    onchange: (value: string | undefined) => void;
  } = $props();

  let open = $state(false);
  let draft = $state("");
  let cut = $state(false);
  let original: string | undefined;
  const hintId = $props.id();

  const label = $derived(comment ? `${t("Comment")}: ${comment}` : t("Comment"));

  function onOpenChange(next: boolean) {
    if (!next) return;
    original = comment;
    draft = comment ?? "";
    cut = false;
  }

  let field = $state<HTMLTextAreaElement>();

  function grow() {
    if (!field) return;
    field.style.height = "auto";
    field.style.height = `${field.scrollHeight + field.offsetHeight - field.clientHeight}px`;
  }

  $effect(() => {
    void draft;
    grow();
  });

  function onInput(event: Event & { currentTarget: HTMLTextAreaElement }) {
    const value = event.currentTarget.value;
    if (utf8Length(value) > COMMENT_MAX_BYTES) {
      draft = cutToBytes(value);
      event.currentTarget.value = draft;
      cut = true;
    } else {
      draft = value;
    }
    apply(cleanComment(draft));
  }

  function apply(next: string | undefined) {
    if (next !== comment) onchange(next);
  }

  function onKeydown(event: KeyboardEvent) {
    if (event.key !== "Enter" || event.isComposing) return;
    event.preventDefault();
    open = false;
  }
</script>

<Popover.Root bind:open {onOpenChange}>
  <Tooltip value={comment ?? t("Comment")}>
    <Popover.Trigger
      class={comment ? "rule-comment set" : "rule-comment"}
      aria-label={label}
      data-search-match={matched ? "true" : undefined}
    >
      <Comment size={18} />
    </Popover.Trigger>
  </Tooltip>
  <Popover.Portal>
    <Popover.Content
      class="rule-comment-editor"
      side="bottom"
      align="end"
      sideOffset={6}
      collisionPadding={8}
      onEscapeKeydown={() => apply(original)}
    >
      <textarea
        rows="1"
        class="rule-comment-input"
        aria-label={t("Comment")}
        placeholder={t("Comment")}
        enterkeyhint="done"
        aria-describedby={cut ? hintId : undefined}
        bind:this={field}
        value={draft}
        oninput={onInput}
        onkeydown={onKeydown}
      ></textarea>
      {#if cut}
        <div class="rule-comment-hint" id={hintId} role="status">{t("Up to 256 bytes")}</div>
      {/if}
    </Popover.Content>
  </Popover.Portal>
</Popover.Root>

<style>
  :global(.rule-comment) {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 0.4rem;
    border: none;
    border-radius: 8px;
    background: transparent;
    color: color-mix(in oklab, var(--text-2) 40%, transparent);
    cursor: pointer;
  }

  :global(.rule-comment:hover),
  :global(.rule-comment:focus-visible) {
    color: var(--text-2);
    background-color: var(--bg-light);
  }

  :global(.rule-comment.set),
  :global(.rule-comment.set:hover) {
    color: var(--accent);
  }

  :global(.rule-comment[data-search-match="true"]) {
    background: color-mix(in oklab, var(--yellow) 34%, transparent);
  }

  :global(.rule-comment-editor) {
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
    width: 20rem;
    max-width: calc(100vw - 1rem);
    box-sizing: border-box;
    padding: 0.5rem 0.6rem;
    background-color: var(--bg-dark-extra);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    box-shadow: var(--shadow-popover);
    color: var(--text);
    z-index: 30;
    outline: none;
  }

  .rule-comment-input {
    display: block;
    width: 100%;
    max-height: 10rem;
    box-sizing: border-box;
    resize: none;
    overflow-y: auto;
    line-height: 1.35;
    padding: 0.2rem 0;
    border: none;
    border-bottom: 1px solid var(--bg-light-extra);
    background: transparent;
    color: var(--text);
    font-family: var(--font);
    font-size: 1rem;
    outline: none;
  }

  .rule-comment-input:focus-visible {
    border-bottom-color: var(--accent);
  }

  .rule-comment-hint {
    color: var(--text-2);
    font-size: 0.75rem;
  }
</style>
