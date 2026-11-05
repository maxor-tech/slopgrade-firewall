// PROOF FIXTURE, never merged. A parameter reaches a shell: the library threat model must report line 5.
import { exec } from "node:child_process";

export function runCommand(cmd) {
  return exec(cmd);
}

// Negative control: a constant command, so this must stay silent.
export function statusCommand() {
  return exec("git status");
}
