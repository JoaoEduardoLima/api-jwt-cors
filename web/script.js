async function makeRequestLogin() {
    var uname = document.getElementById("uname").value;
    var psw = document.getElementById("psw").value;
  
    let response = await fetch('http://localhost:3010/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: `login=${encodeURIComponent(uname)}&senha=${encodeURIComponent(psw)}`
    });
  
    let result = await response.json();
  
    // Salvar o token no local storage
    localStorage.setItem('token', response.headers.get('Authorization'));
  
    document.getElementById("response").innerHTML = JSON.stringify(result);
  }
  
  async function makeRequestLogado() {
      let response = await fetch('http://localhost:3010/api/v1', {
      method: 'GET',
      headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': localStorage.getItem('token')
      }
  });
  
      let result = await response.json();
  
      document.getElementById("response").innerHTML = JSON.stringify(result);
  }
  
  async function makeRequestLogout() {
      let response = await fetch('http://localhost:3010/api/v1/logout', {
      method: 'POST',
      headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': localStorage.getItem('token')
      }
  });
  
      let result = await response.json();
  
      document.getElementById("response").innerHTML = JSON.stringify(result);
  }