import React, { useState } from 'react';
import axiosInstance from '../api/axiosInstance';
import {
  Container,
  Typography,
  TextField,
  MenuItem,
  Button,
  Paper,
  Box
} from '@mui/material';
import { useNavigate } from 'react-router-dom';

const scanTypes = [
  { value: 'host_discovery', label: 'Host Discovery' },
  { value: 'open_ports', label: 'Open Ports' },
  { value: 'os_services', label: 'OS, Services, and Version Detection' },
];

const CreateScanPage = () => {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleCreate = async (e) => {
    e.preventDefault();
    setError('');

    try {
      await axiosInstance.post('scans/', {
        name,
        description,
        target,
        scan_type: scanType,
      });
      navigate('/v1/dashboard');
    } catch (err) {
      console.error(err);
      setError('Failed to create scan. Please check your input.');
    }
  };

  return (
    <Container sx={{ mt: 4 }}>
      <Paper elevation={3} sx={{ p: 4 }}>
        <Typography variant="h4" gutterBottom>Create New Scan</Typography>

        <Box component="form" onSubmit={handleCreate} sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <TextField
            label="Scan Name"
            variant="outlined"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
          <TextField
            label="Description"
            variant="outlined"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            multiline
            rows={2}
          />
          <TextField
            label="Target (IP, IP range, or domain)"
            variant="outlined"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            required
          />
          <TextField
            select
            label="Scan Type"
            value={scanType}
            onChange={(e) => setScanType(e.target.value)}
            required
          >
            {scanTypes.map((option) => (
              <MenuItem key={option.value} value={option.value}>
                {option.label}
              </MenuItem>
            ))}
          </TextField>

          <Button type="submit" variant="contained" color="primary">
            Create Scan
          </Button>

          {error && <Typography color="error">{error}</Typography>}
        </Box>
      </Paper>
    </Container>
  );
};

export default CreateScanPage;
