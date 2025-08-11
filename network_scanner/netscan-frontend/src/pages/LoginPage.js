import React, { useState, useContext } from 'react';
import {
  Box,
  TextField,
  Button,
  Paper,
  Typography,
  InputAdornment,
  IconButton
} from '@mui/material';
import { useNavigate } from 'react-router-dom';
import AuthContext from '../auth/AuthContext';
import { Visibility, VisibilityOff } from '@mui/icons-material';

import Particles from "react-tsparticles";
import { loadFull } from "tsparticles";
import axiosInstance from '../api/axiosInstance';
const LoginPage = () => {
  const { login } = useContext(AuthContext);
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');

  const particlesInit = async (main) => {
    await loadFull(main);
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
  
    try {
      const { data } = await axiosInstance.post('token/', { username, password });
      await login(data.access, data.refresh);
      navigate('/v1/dashboard');
    } catch (err) {
      console.error(err);
      if (err.response?.data?.detail) {
        setError(err.response.data.detail);
      } else {
        setError('Login failed. Please try again.');
      }
    }
  };
  

  return (
    <Box sx={{ position: 'relative', height: '100vh', overflow: 'hidden' }}>
      {/* Particles.js background */}
      <Particles
        id="particles-js"
        init={particlesInit}
        options={{
          particles: {
            number: {
              value: 398,
              density: {
                enable: false,
                value_area: 2578
              }
            },
            color: { value: "#00000" },
            shape: {
              type: "circle",
              stroke: { width: 0, color: "#000000" },
              polygon: { nb_sides: 5 }
            },
            opacity: {
              value: 0.35,
              random: false
            },
            size: {
              value: 1.5,
              random: true
            },
            line_linked: {
              enable: true,
              distance: 208,
              color: "#a20775",
              opacity: 0.4,
              width: 2
            },
            move: {
              enable: true,
              speed: 2,
              direction: "none",
              random: false,
              straight: false,
              out_mode: "out",
              bounce: false,
              attract: {
                enable: true,
                rotateX: 600,
                rotateY: 1200
              }
            }
          },
          interactivity: {
            detect_on: "window",
            events: {
              onhover: { enable: true, mode: "repulse" },
              onclick: { enable: true, mode: "push" },
              resize: true
            },
            modes: {
              grab: {
                distance: 694,
                line_linked: { opacity: 1 }
              },
              bubble: {
                distance: 400,
                size: 40,
                duration: 5,
                opacity: 8,
                speed: 30
              },
              repulse: {
                distance: 100,
                duration: 0.1
              },
              push: { particles_nb: 4 },
              remove: { particles_nb: 2 }
            }
          },
          retina_detect: true
        }}
        style={{ position: 'absolute', top: 0, left: 0, zIndex: 0 }}
      />

      {/* Login form */}
      <Box
        sx={{
          position: 'relative',
          zIndex: 1,
          height: '100vh',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
        }}
      >
        <Paper elevation={6} sx={{ p: 5, width: 400, backgroundColor: 'rgba(255, 255, 255, 0.85)' }}>
          <Typography variant="h4" gutterBottom align="center">
            Login
          </Typography>

          <Box component="form" onSubmit={handleLogin} sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <TextField
              label="Username"
              variant="outlined"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              fullWidth
              required
            />
            <TextField
              label="Password"
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              fullWidth
              required
              variant="outlined"
              InputProps={{
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton onClick={() => setShowPassword(!showPassword)} edge="end">
                      {showPassword ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  </InputAdornment>
                )
              }}
            />
            {error && <Typography color="error">{error}</Typography>}
            <Button type="submit" variant="contained" color="primary" fullWidth>
              Login
            </Button>
          </Box>
        </Paper>
      </Box>
    </Box>
  );
};

export default LoginPage;
