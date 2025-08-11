import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axiosInstance from '../api/axiosInstance';
import { Container, Typography, TextField, MenuItem, Button, Paper, Box } from '@mui/material';

const scanTypes = [
  { value: 'host_discovery', label: 'Host Discovery' },
  { value: 'open_ports', label: 'Open Ports' },
  { value: 'os_services', label: 'OS, Services, and Version Detection' },
];

const EditScanPage = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    fetchScan();
  }, []);

  const fetchScan = async () => {
    try {
      const response = await axiosInstance.get(`scans/${id}/`);
      const scan = response.data;
      setName(scan.name);
      setDescription(scan.description);
      setTarget(scan.target);
      setScanType(scan.scan_type);
    } catch (err) {
      console.error('Failed to fetch scan', err);
    }
  };

  const handleUpdate = async (e) => {
    e.preventDefault();
    setError('');

    try {
      await axiosInstance.put(`scans/${id}/`, {
        name,
        description,
        target,
        scan_type: scanType,
      });
      navigate('/v1/dashboard');
    } catch (err) {
      console.error(err);
      setError('Failed to update scan. Please check your input.');
    }
  };

  return (
    <Container sx={{ mt: 4 }}>
      <Paper elevation={3} sx={{ p: 4 }}>
        <Typography variant="h4" gutterBottom>Edit Scan</Typography>
        <Typography variant="subtitle1" color="textSecondary">Scan ID: {id}</Typography>

        <Box component="form" onSubmit={handleUpdate} sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
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
            Update Scan
          </Button>

          {error && <Typography color="error">{error}</Typography>}
        </Box>
      </Paper>
    </Container>
  );
};

export default EditScanPage;
