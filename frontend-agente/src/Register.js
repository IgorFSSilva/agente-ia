// src/Register.js
import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

function Register() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const navigate = useNavigate();

  const handleRegister = async (e) => {
    e.preventDefault();
    try {
      await axios.post('https://agente-ia-jawq.onrender.com/api/register', {
        email,
        password,
      });
      alert('Cadastro realizado com sucesso!');
      navigate('/login');
    } catch (err) {
      alert('Erro no cadastro: ' + err.response?.data?.error || err.message);
    }
  };

  return (
    <div className="auth-form">
      <h2>Cadastrar</h2>
      <form onSubmit={handleRegister}>
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
        <button type="submit">Cadastrar</button>
        <p onClick={() => navigate('/login')} className="link">Já tem conta? Entrar</p>
      </form>
    </div>
  );
}

export default Register;
