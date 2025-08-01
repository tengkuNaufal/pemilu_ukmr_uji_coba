async function fetchCandidates() {
  const res = await fetch('/api/candidates', {
    headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
  });
  if (!res.ok) return alert('Gagal ambil kandidat');
  return res.json();
}

document.addEventListener('DOMContentLoaded', async () => {
  const candidates = await fetchCandidates();
  const container = document.getElementById('kandidatContainer');

  candidates.forEach(c => {
    const card = document.createElement('div');
    card.className = 'bg-white p-6 rounded-xl shadow-lg flex flex-col items-center space-y-4';
    card.innerHTML = `
      <img src="${c.foto_url}" class="w-32 h-32 rounded-full object-cover border-4 border-green-500">
      <h2 class="text-xl font-bold">${c.nama}</h2>
      <p class="italic text-sm text-gray-600">${c.visi.slice(0, 100)}...</p>
      <button class="voteBtn bg-green-600 hover:bg-green-700 text-white p-2 rounded-lg w-full" data-id="${c.id}">Pilih</button>
    `;
    container.appendChild(card);
  });

  container.addEventListener('click', async e => {
    if (!e.target.matches('.voteBtn')) return;
    const candidate_id = e.target.dataset.id;
    if (!confirm('Yakin memilih kandidat ini?')) return;

    const res = await fetch('/api/vote', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + localStorage.getItem('token')
      },
      body: JSON.stringify({ candidate_id })
    });
    if (res.ok) {
      alert('Voting berhasil!');
      window.location.href = 'thankyou.html';
    } else {
      const { message } = await res.json();
      alert('Gagal: ' + message);
    }
  });
});
