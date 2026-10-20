let current = $state<{ group: string; seq: number } | null>(null);
let seq = 0;

export const journalFocus = {
  get request() {
    return current;
  },
  open(group: string) {
    current = { group, seq: ++seq };
  },
};
