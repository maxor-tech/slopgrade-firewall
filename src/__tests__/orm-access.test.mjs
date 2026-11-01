// ORM by-id access (src/orm-access.mjs) : the Django ORM / ActiveRecord / Spring Data / GORM models and by-id queries
// the cross-tenant fingerprint reads for the server's advisory IDOR check. Only by-id accesses are emitted.
import { test } from "node:test";
import assert from "node:assert/strict";
import { extractOrmModels, extractOrmQueries, modelKey } from "../orm-access.mjs";

const q = (code, file) => extractOrmQueries(code, file).map(({ orm, model, whereIdCols }) => ({ orm, model, whereIdCols }));

test("model keys are singular snake_case", () => {
  assert.equal(modelKey("InvoiceItem"), "invoice_item");
  assert.equal(modelKey("invoice_items"), "invoice_item");
  assert.equal(modelKey("companies"), "company");
  assert.equal(modelKey("Address"), "address");
});

test("models : Django, Rails schema.rb, JPA @Entity, GORM struct — a foreign key becomes <name>_id", () => {
  assert.deepEqual(extractOrmModels(`class Invoice(models.Model):\n    org = models.ForeignKey(Org, on_delete=models.CASCADE)\n    amount = models.IntegerField()\n`, "billing/models.py"),
    [{ model: "invoice", cols: ["id", "org_id", "amount"] }]);
  assert.deepEqual(extractOrmModels(`  create_table "invoices", force: :cascade do |t|\n    t.references "org"\n    t.integer "amount"\n  end\n`, "db/schema.rb"),
    [{ model: "invoice", cols: ["id", "org_id", "amount"] }]);
  assert.deepEqual(extractOrmModels(`@Entity\npublic class Invoice {\n  @Id private UUID id;\n  @ManyToOne\n  private Org org;\n  private int amount;\n}\n`, "Invoice.java"),
    [{ model: "invoice", cols: ["id", "org_id", "amount"] }]);
  assert.deepEqual(extractOrmModels(`import "gorm.io/gorm"\ntype Invoice struct {\n  gorm.Model\n  OrgID uuid.UUID\n  Amount int\n}\n`, "model.go"),
    [{ model: "invoice", cols: ["id", "org_id", "amount"] }]);
});

test("CONTROL : a non-model Python class, a Go struct in a file without gorm, a Java class without @Entity", () => {
  assert.deepEqual(extractOrmModels(`class Form(forms.Form):\n    name = forms.CharField()\n`, "forms.py"), []);
  assert.deepEqual(extractOrmModels(`type Config struct {\n  OrgID string\n}\n`, "config.go"), []);
  assert.deepEqual(extractOrmModels(`public class Invoice {\n  private String orgId;\n}\n`, "Invoice.java"), []);
});

test("by-id queries : Django get / get_object_or_404, Rails find / find_by, Spring findById, GORM First", () => {
  assert.deepEqual(q(`inv = Invoice.objects.get(pk=request.GET["id"])`, "views.py"), [{ orm: "django", model: "invoice", whereIdCols: ["id"] }]);
  assert.deepEqual(q(`inv = get_object_or_404(Invoice, pk=pk, org=request.user.org)`, "views.py"), [{ orm: "django", model: "invoice", whereIdCols: ["id", "org"] }]);
  assert.deepEqual(q(`@invoice = Invoice.find(params[:id])`, "c.rb"), [{ orm: "rails", model: "invoice", whereIdCols: ["id"] }]);
  assert.deepEqual(q(`@invoice = Invoice.where(org_id: current_org.id).find(params[:id])`, "c.rb"), [{ orm: "rails", model: "invoice", whereIdCols: ["org_id", "id"] }]);
  assert.deepEqual(q(`return invoiceRepository.findById(id).orElseThrow();`, "C.java"), [{ orm: "spring", model: "invoice", whereIdCols: ["id"] }]);
  assert.deepEqual(q(`return invoiceRepository.findByIdAndOrgId(id, org);`, "C.java"), [{ orm: "spring", model: "invoice", whereIdCols: ["id", "org_id"] }]);
  assert.deepEqual(q(`var inv Invoice\ndb.First(&inv, "id = ?", c.Param("id"))`, "h.go"), [{ orm: "gorm", model: "invoice", whereIdCols: ["id"] }]);
  assert.deepEqual(q(`db.Delete(&Invoice{}, id)`, "h.go"), [{ orm: "gorm", model: "invoice", whereIdCols: ["id"] }]);
});

test("CONTROL : no id in the filter, or a relation-scoped find, is not emitted", () => {
  assert.deepEqual(q(`qs = Invoice.objects.filter(status="open")`, "views.py"), []);
  assert.deepEqual(q(`@invoice = current_user.invoices.find(params[:id])`, "c.rb"), []);
  assert.deepEqual(q(`return invoiceRepository.findAllByStatus(s);`, "C.java"), []);
  assert.deepEqual(q(`var invs []Invoice\ndb.Where("status = ?", s).Find(&invs)`, "h.go"), []);
});

test("egress : the sanitizer passes ORM models and queries as identifiers and booleans only", async () => {
  const { sanitizeFingerprint } = await import("../client-lib.mjs");
  const s = sanitizeFingerprint({
    ormModels: { invoice: ["id", "org_id"], __proto__: ["x"] },
    ormQueries: [{ orm: "django", table: "invoice", whereIdCols: ["id"], isAdmin: 0, idFromRequest: true, ownerCheckNear: false, file: "v.py", line: 3, source: "SECRET LINE" }],
  });
  assert.deepEqual(s.ormModels, { invoice: ["id", "org_id"] });
  assert.deepEqual(s.ormQueries, [{ orm: "django", table: "invoice", whereIdCols: ["id"], isAdmin: false, idFromRequest: true, ownerCheckNear: false, file: "v.py", line: 3 }]);
});
