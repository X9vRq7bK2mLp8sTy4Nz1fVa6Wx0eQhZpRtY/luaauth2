function login() {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  fetch('/api/admin/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  }).then(res => res.json())
    .then(data => {
      if (data.error) alert(data.error);
      else {
        localStorage.setItem('sessionToken', data.sessionToken);
        document.getElementById('login').style.display = 'none';
        document.getElementById('admin').style.display = 'block';
      }
    }).catch(err => alert(err));
}

function createScript() {
  const payload = document.getElementById('payload').value;
  const sessionToken = localStorage.getItem('sessionToken');
  fetch('/api/admin/create', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-session-token': sessionToken
    },
    body: JSON.stringify({ payload })
  }).then(res => res.json())
    .then(data => {
      if (data.error) alert(data.error);
      else document.getElementById('url').innerText = `Raw URL: ${data.rawUrl}`;
    }).catch(err => alert(err));
}
