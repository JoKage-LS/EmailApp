module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { names } = req.body;
  if (!names || !Array.isArray(names)) return res.status(400).json({ error: 'names array required' });

  const PCO_APP_ID = process.env.PCO_APP_ID;
  const PCO_SECRET = process.env.PCO_SECRET;

  if (!PCO_APP_ID || !PCO_SECRET) {
    return res.status(500).json({ error: 'Planning Center credentials not configured. Add PCO_APP_ID and PCO_SECRET to your Vercel environment variables.' });
  }

  const auth = Buffer.from(`${PCO_APP_ID}:${PCO_SECRET}`).toString('base64');
  const results = [];

  for (const name of names) {
    const trimmed = name.trim();
    if (!trimmed) continue;

    try {
      const searchName = encodeURIComponent(trimmed);
      const url = `https://api.planningcenteronline.com/people/v2/people?where[search_name]=${searchName}&fields[Person]=first_name,last_name,primary_email_address&include=emails&per_page=5`;

      const response = await fetch(url, {
        headers: {
          'Authorization': `Basic ${auth}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        results.push({ name: trimmed, status: 'error', message: `PCO error: ${response.status}` });
        continue;
      }

      const data = await response.json();
      const people = data.data || [];
      const included = data.included || [];

      if (people.length === 0) {
        results.push({ name: trimmed, status: 'not_found', message: 'Not found in Planning Center' });
        continue;
      }

      const nameParts = trimmed.toLowerCase().split(' ');
      let bestMatch = people[0];
      for (const person of people) {
        const fn = (person.attributes.first_name || '').toLowerCase();
        const ln = (person.attributes.last_name || '').toLowerCase();
        if (nameParts.length >= 2 && fn === nameParts[0] && ln === nameParts[nameParts.length - 1]) {
          bestMatch = person;
          break;
        }
      }

      const personId = bestMatch.id;
      const emailRels = bestMatch.relationships?.emails?.data || [];
      let email = null;

      for (const emailRel of emailRels) {
        const emailObj = included.find(i => i.type === 'Email' && i.id === emailRel.id);
        if (emailObj) {
          if (emailObj.attributes.primary || !email) {
            email = emailObj.attributes.address;
          }
          if (emailObj.attributes.primary) break;
        }
      }

      if (!email) {
        const emailUrl = `https://api.planningcenteronline.com/people/v2/people/${personId}/emails?where[primary]=true`;
        const emailRes = await fetch(emailUrl, {
          headers: { 'Authorization': `Basic ${auth}` }
        });
        if (emailRes.ok) {
          const emailData = await emailRes.json();
          if (emailData.data && emailData.data.length > 0) {
            email = emailData.data[0].attributes.address;
          }
        }
      }

      if (!email) {
        results.push({
          name: trimmed,
          status: 'no_email',
          message: 'Found in PCO but no email address on file',
          firstName: bestMatch.attributes.first_name,
          lastName: bestMatch.attributes.last_name,
          pcoId: personId
        });
        continue;
      }

      results.push({
        name: trimmed,
        status: 'found',
        firstName: bestMatch.attributes.first_name,
        lastName: bestMatch.attributes.last_name,
        email,
        pcoId: personId
      });

    } catch (err) {
      results.push({ name: trimmed, status: 'error', message: err.message });
    }
  }

  return res.status(200).json({ results });
}
