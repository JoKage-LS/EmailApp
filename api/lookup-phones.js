module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { rows } = req.body;
  if (!rows || !Array.isArray(rows)) return res.status(400).json({ error: 'rows array required' });
  if (rows.length === 0)             return res.status(400).json({ error: 'rows array is empty' });
  if (rows.length > 300)             return res.status(400).json({ error: 'Max 300 rows per request — split into batches' });

  const PCO_APP_ID = process.env.PCO_APP_ID;
  const PCO_SECRET = process.env.PCO_SECRET;
  if (!PCO_APP_ID || !PCO_SECRET) {
    return res.status(500).json({ error: 'Planning Center credentials not configured.' });
  }

  const auth    = Buffer.from(`${PCO_APP_ID}:${PCO_SECRET}`).toString('base64');
  const headers = { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/json' };

  const results = [];

  for (const row of rows) {
    const firstName = (row.firstName || '').trim();
    const lastName  = (row.lastName  || '').trim();

    const base = {
      firstName,
      lastName,
      passthrough: row.passthrough || {},
      mobile: '',
      mobileSource: '',
      matchStatus: 'Not Found',
      notes: ''
    };

    if (!firstName || !lastName) {
      results.push({ ...base, notes: 'Missing first or last name' });
      continue;
    }

    try {
      // 1. Search by exact first + last name
      const searchUrl = `https://api.planningcenteronline.com/people/v2/people` +
        `?where[first_name]=${encodeURIComponent(firstName)}` +
        `&where[last_name]=${encodeURIComponent(lastName)}` +
        `&include=phone_numbers,households` +
        `&per_page=25`;

      const searchRes = await fetch(searchUrl, { headers });
      if (!searchRes.ok) {
        results.push({ ...base, matchStatus: 'Error', notes: `PCO ${searchRes.status}` });
        continue;
      }

      const searchData = await searchRes.json();
      const people     = searchData.data     || [];
      const included   = searchData.included || [];

      if (people.length === 0) {
        results.push({ ...base, matchStatus: 'Not Found' });
        continue;
      }

      if (people.length > 1) {
        results.push({
          ...base,
          matchStatus: 'Multiple Matches',
          notes: `${people.length} people in PCO with this name`
        });
        continue;
      }

      const person = people[0];

      // 2. Try the youth's own mobile number from included phone_numbers
      const phoneRels = person.relationships?.phone_numbers?.data || [];
      const youthPhones = phoneRels
        .map(rel => included.find(i => i.type === 'PhoneNumber' && i.id === rel.id))
        .filter(Boolean);

      const youthMobile = pickMobile(youthPhones);
      if (youthMobile) {
        results.push({
          ...base,
          mobile: youthMobile,
          mobileSource: 'Youth',
          matchStatus: 'Matched'
        });
        await sleep(150);
        continue;
      }

      // 3. Fall back to household — get household members and their phones
      const householdRels = person.relationships?.households?.data || [];
      if (householdRels.length === 0) {
        results.push({
          ...base,
          matchStatus: 'Matched',
          notes: 'Found but no mobile, no household linked'
        });
        await sleep(150);
        continue;
      }

      const householdId = householdRels[0].id;
      const memberUrl = `https://api.planningcenteronline.com/people/v2/households/${householdId}/people` +
        `?include=phone_numbers&per_page=25`;
      const memberRes = await fetch(memberUrl, { headers });

      if (!memberRes.ok) {
        results.push({
          ...base,
          matchStatus: 'Matched',
          notes: `Found but household lookup failed (${memberRes.status})`
        });
        await sleep(150);
        continue;
      }

      const memberData     = await memberRes.json();
      const members        = memberData.data     || [];
      const memberIncluded = memberData.included || [];

      // Find adults (child=false) who aren't the youth themselves
      const adults = members.filter(m => !m.attributes.child && m.id !== person.id);

      let parentMobile = null;
      let parentName   = null;

      for (const adult of adults) {
        const adultPhoneRels = adult.relationships?.phone_numbers?.data || [];
        const adultPhones = adultPhoneRels
          .map(rel => memberIncluded.find(i => i.type === 'PhoneNumber' && i.id === rel.id))
          .filter(Boolean);

        const m = pickMobile(adultPhones);
        if (m) {
          parentMobile = m;
          parentName   = adult.attributes.name || `${adult.attributes.first_name} ${adult.attributes.last_name}`.trim();
          break;
        }
      }

      if (parentMobile) {
        results.push({
          ...base,
          mobile: parentMobile,
          mobileSource: `Parent (${parentName})`,
          matchStatus: 'Matched'
        });
      } else {
        results.push({
          ...base,
          matchStatus: 'Matched',
          notes: 'Found but no mobile on profile or household'
        });
      }

    } catch (err) {
      results.push({ ...base, matchStatus: 'Error', notes: err.message });
    }

    await sleep(150); // throttle to stay under PCO rate limits
  }

  const summary = {
    total: results.length,
    matched: results.filter(r => r.matchStatus === 'Matched' && r.mobile).length,
    matchedNoMobile: results.filter(r => r.matchStatus === 'Matched' && !r.mobile).length,
    notFound: results.filter(r => r.matchStatus === 'Not Found').length,
    multipleMatches: results.filter(r => r.matchStatus === 'Multiple Matches').length,
    errors: results.filter(r => r.matchStatus === 'Error').length
  };

  return res.status(200).json({ results, summary });
};

function pickMobile(phones) {
  if (!phones || phones.length === 0) return null;
  const mobiles = phones.filter(p => (p.attributes.location || '').toLowerCase() === 'mobile');
  const primaryMobile = mobiles.find(p => p.attributes.primary);
  if (primaryMobile) return primaryMobile.attributes.number;
  if (mobiles.length > 0) return mobiles[0].attributes.number;
  return null;
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}
