// PROOF FIXTURE, never merged. Expected: LOW library-command-injection on line 5.
import { exec } from "node:child_process";

export function runCommand(cmd) {
  return exec(cmd);
}
