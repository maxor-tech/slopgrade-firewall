// PROOF FIXTURE, never merged. Control: a plain test labels a path and guards nothing, so it stays silent.
import java.io.File;
class ProofLabel {
  String label(File dir, File target) throws Exception {
    if (target.getCanonicalPath().startsWith(dir.getCanonicalPath())) return "inside";
    return "outside";
  }
}
