// src/Login.js
import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('https://agente-ia-jawq.onrender.com/api/login', {
        email,
        password,
      });
      localStorage.setItem('token', response.data.token);
      navigate('/dashboard');
    } catch (err) {
      alert('Login falhou: ' + err.response?.data?.error || err.message);
    }
  };

  return (
    <div className="auth-form">
      <h2>Entrar</h2>
      <form onSubmit={handleLogin}>
        <input
          type="email"
          placeholder="E-mail"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <input
          type="password"
          placeholder="Senha"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        <button type="submit">Entrar</button>
        <p onClick={() => navigate('/register')} className="link">Não tem conta? Cadastre-se</p>
      </form>
    </div>
  );
}

export default Login;
