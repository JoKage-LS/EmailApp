module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { query } = req.body;
  if (!query || typeof query !== 'string' || !query.trim()) {
    return res.status(400).json({ error: 'query string required' });
  }

  const PCO_APP_ID = process.env.PCO_APP_ID;
  const PCO_SECRET = process.env.PCO_SECRET;
  if (!PCO_APP_ID || !PCO_SECRET) {
    return res.status(500).json({ error: 'Planning Center credentials not configured.' });
  }

  const auth = Buffer.from(`${PCO_APP_ID}:${PCO_SECRET}`).toString('base64');

  try {
    const searchName = encodeURIComponent(query.trim());
    const url = `https://api.planningcenteronline.com/people/v2/people?where[search_name]=${searchName}&fields[Person]=first_name,last_name&include=emails&per_page=10`;

    const response = await fetch(url, {
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      return res.status(502).json({ error: `PCO error: ${response.status}` });
    }

    const data     = await response.json();
    const people   = data.data     || [];
    const included = data.included || [];

    const results = people.map(person => {
      const personId  = person.id;
      const firstName = person.attributes.first_name || '';
      const lastName  = person.attributes.last_name  || '';

      // Try to get primary email from included data
      const emailRels = person.relationships?.emails?.data || [];
      let email = null;
      for (const rel of emailRels) {
        const obj = included.find(i => i.type === 'Email' && i.id === rel.id);
        if (obj) {
          if (obj.attributes.primary || !email) email = obj.attributes.address;
          if (obj.attributes.primary) break;
        }
      }

      return { pcoId: personId, firstName, lastName, email };
    });

    return res.status(200).json({ results });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
};
