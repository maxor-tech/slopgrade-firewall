// PROOF FIXTURE, never merged. Control: this factory only makes an empty DOM, and .build( is unrelated, so it stays silent.
import javax.xml.parsers.DocumentBuilderFactory;
class ProofEmpty {
  Object make(Object other) throws Exception {
    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
    Object d = f.newDocumentBuilder().newDocument();
    return Holder.builder().with(d).build();
  }
}
