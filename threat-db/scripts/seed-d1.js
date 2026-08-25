const fs = require('fs');
const path = require('path');

const THREATS_JSON = path.join(__dirname, '../data/threats.json');
const OUTPUT_SQL = path.join(__dirname, '../../web/seed-threats.sql');

function generateSeedSql() {
  if (!fs.existsSync(THREATS_JSON)) {
    console.error(`threats.json not found at ${THREATS_JSON}. Run compile.js first.`);
    return;
  }

  const threats = JSON.parse(fs.readFileSync(THREATS_JSON, 'utf8'));
  const sqlStatements = [];

  for (const t of threats) {
    const id = (t.id || '').replace(/'/g, "''");
    const name = (t.name || '').replace(/'/g, "''");
    const severity = (t.severity || 'MEDIUM').replace(/'/g, "''");
    const category = (t.category || 'General').replace(/'/g, "''");
    const description = (t.description || '').replace(/'/g, "''");
    const remediation = (t.remediation || '').replace(/'/g, "''");
    const patternHash = (t.pattern_hash || '').replace(/'/g, "''");
    const createdAt = (t.created_at || new Date().toISOString()).replace(/'/g, "''");

    sqlStatements.push(
      `INSERT OR REPLACE INTO threats (id, name, severity, category, description, remediation, pattern_hash, created_at) VALUES ('${id}', '${name}', '${severity}', '${category}', '${description}', '${remediation}', '${patternHash}', '${createdAt}');`
    );
  }

  fs.writeFileSync(OUTPUT_SQL, sqlStatements.join('\n'));
  console.log(`Generated ${sqlStatements.length} seed statements to ${OUTPUT_SQL}`);
}

generateSeedSql();
