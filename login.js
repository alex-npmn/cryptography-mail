document.getElementById('login-form').addEventListener('submit', (event) => {
    event.preventDefault();

    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    // TODO: Pass email and password to your Python backend to log in and generate keys
    console.log('Email:', email);
    console.log('Password:', password);
});
