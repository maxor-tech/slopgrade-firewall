// PROOF FIXTURE, never merged. Expected: MEDIUM library-path-traversal on line 5.
import java.io.File;
class ProofGuard {
  void check(File dir, File target) throws Exception {
    if (!target.getCanonicalPath().startsWith(dir.getCanonicalPath())) throw new SecurityException();
  }
}
