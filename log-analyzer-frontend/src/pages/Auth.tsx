import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom'; 
import './Auth.css';

const Auth: React.FC = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const navigate = useNavigate(); 
  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    const endpoint = isLogin ? '/login' : '/register';
    // Login and register functionality
    try 
    {
      const response = await axios.post(`http://localhost:5000/${endpoint}`, {
      username,
      password
      }, {withCredentials: true});
      setMessage(response.data.message);

      // Redirect only after successful login
      if (isLogin && response.data.message === 'Login successful') 
      {
        navigate('/upload');
      }
    } 
    catch (error: any) 
    {
      setMessage(error.response?.data?.error || 'Something went wrong');
    }
  };
return (
  <div className="auth-container">
    <h2>{isLogin ? 'Login' : 'Sign up'}</h2>
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        placeholder="Username"
        value={username}
        onChange={e => setUsername(e.target.value)}
        required
      />
      <input
        type="password"
        placeholder="Password"
        value={password}
        onChange={e => setPassword(e.target.value)}
        required
      />
      <button type="submit">{isLogin ? 'Submit' : 'Sign up'}</button>
    </form>
    <p>{message}</p>
    <button onClick={() => setIsLogin(!isLogin)}>
      {isLogin ? 'Sign up' : 'Login'}
    </button>
  </div>
);
};

export default Auth;
