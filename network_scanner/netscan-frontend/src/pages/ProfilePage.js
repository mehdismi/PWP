import React, { useContext, useState } from 'react';
import { Container, Typography, TextField, Button, Paper, Box } from '@mui/material';
import axiosInstance from '../api/axiosInstance';
import AuthContext from '../auth/AuthContext';

const ProfilePage = () => {
  const { user, logout } = useContext(AuthContext);

  const [firstName, setFirstName] = useState(user?.first_name || '');
  const [lastName, setLastName] = useState(user?.last_name || '');
  const [username, setUsername] = useState(user?.username || '');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  const handleUpdateProfile = async (e) => {
    e.preventDefault();
    setError('');
    setMessage('');

    try {
      await axiosInstance.put(`accounts/profile/${user?.id}/`, {
        first_name: firstName,
        last_name: lastName,
        username: username,
      });
      setMessage('Profile updated successfully.');
    } catch (err) {
      console.error(err);
      setError('Failed to update profile.');
    }
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();
    setError('');
    setMessage('');

    if (!currentPassword || !newPassword) {
      setError('Please fill in both password fields.');
      return;
    }

    try {
      await axiosInstance.put('accounts/change-password/', {
        old_password: currentPassword,
        new_password: newPassword,
      });
      setMessage('Password changed successfully.');
      setCurrentPassword('');
      setNewPassword('');
      logout();
    } catch (err) {
      console.error(err);
      setError('Failed to change password.');
    }
  };

  return (
    <Container sx={{ mt: 4 }}>
      <Paper elevation={3} sx={{ p: 4 }}>
        <Typography variant="h4" gutterBottom>Profile</Typography>
        <Typography variant="subtitle1" color="textSecondary">User ID: {user?.id}</Typography>

        <Box component="form" onSubmit={handleUpdateProfile} sx={{ display: 'flex', flexDirection: 'column', gap: 2, mb: 4 }}>
          <TextField
            label="First Name"
            variant="outlined"
            value={firstName}
            onChange={(e) => setFirstName(e.target.value)}
          />
          <TextField
            label="Last Name"
            variant="outlined"
            value={lastName}
            onChange={(e) => setLastName(e.target.value)}
          />
          <TextField
            label="Username"
            variant="outlined"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <Button type="submit" variant="contained" color="primary">
            Update Profile
          </Button>
        </Box>

        <Typography variant="h5" gutterBottom>Change Password</Typography>

        <Box component="form" onSubmit={handleChangePassword} sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <TextField
            label="Current Password"
            type="password"
            variant="outlined"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
          />
          <TextField
            label="New Password"
            type="password"
            variant="outlined"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
          />
          <Button type="submit" variant="contained" color="secondary">
            Change Password
          </Button>
        </Box>

        {error && <Typography color="error" sx={{ mt: 2 }}>{error}</Typography>}
        {message && <Typography color="success.main" sx={{ mt: 2 }}>{message}</Typography>}
      </Paper>
    </Container>
  );
};

export default ProfilePage;
