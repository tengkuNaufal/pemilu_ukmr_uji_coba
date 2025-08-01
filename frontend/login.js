document.getElementById('loginForm').addEventListener('submit', async function(e) {
  e.preventDefault();
  const nim = document.getElementById('nim').value;
  const password = document.getElementById('password').value;

  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nim, password })
    });
    if (!res.ok) throw new Error();
    const { token } = await res.json();
    localStorage.setItem('token', token);
    window.location.href = 'vote.html';
  } catch {
    document.getElementById('error').classList.remove('hidden');
  }
});
