// PROOF FIXTURE, never merged. Expected: MEDIUM library-xxe on line 5.
import javax.xml.parsers.DocumentBuilderFactory;
class ProofParse {
  Object read(java.io.InputStream in) throws Exception {
    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
    return f.newDocumentBuilder().parse(in);
  }
}
