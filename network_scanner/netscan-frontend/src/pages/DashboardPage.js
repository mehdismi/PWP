import React, { useEffect, useState } from 'react';
import axiosInstance from '../api/axiosInstance';
import {
  Container,
  Typography,
  TextField,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Paper,
  Button,
  LinearProgress,
} from '@mui/material';
import { useNavigate } from 'react-router-dom';

import DeleteIcon from '@mui/icons-material/Delete';
import EditIcon from '@mui/icons-material/Edit';



const DashboardPage = () => {

  const [scans, setScans] = useState([]);
  const [search, setSearch] = useState('');
  const navigate = useNavigate();
  const handleEdit = (scanId) => {
  navigate(`/v1/edit-scan/${scanId}`);
};

const handleDelete = async (scanId) => {
  if (window.confirm('Are you sure you want to delete this scan?')) {
    try {
      await axiosInstance.delete(`scans/${scanId}/`);
      fetchScans();
    } catch (error) {
      console.error('Failed to delete scan', error);
    }
  }
};

  const fetchScans = async () => {
    try {
      const response = await axiosInstance.get(`scans/?search=${search}`);
      setScans(response.data);
    } catch (error) {
      console.error('Failed to fetch scans', error);
    }
  };

  useEffect(() => {
    fetchScans();
  }, [search]);

  const handleRunScan = async (scanId) => {
    try {
      await axiosInstance.post(`scans/${scanId}/run/`);
      fetchScans();
    } catch (error) {
      console.error('Failed to run scan', error);
    }
  };

  const handleCancelScan = async (scanId) => {
    try {
      await axiosInstance.post(`scans/${scanId}/cancel/`);
      fetchScans();
    } catch (error) {
      console.error('Failed to cancel scan', error);
    }
  };

  const handleViewDetails = (scanId) => {
    navigate(`/v1/scan/${scanId}`);
  };

  return (
    <Container sx={{ mt: 4 }}>
  <Typography variant="h4" gutterBottom>Dashboard</Typography>

  {/* Wrapper div to center content and set a max width */}
  <div style={{ width: '100%', margin: '0 auto' }}>
    <TextField
      label="Search Scans"
      variant="outlined"
      fullWidth
      margin="normal"
      value={search}
      onChange={(e) => setSearch(e.target.value)}
    />

    <TableContainer component={Paper}>
      <Table sx={{ minWidth: 800 }}>
        <TableHead>
          <TableRow>
            <TableCell>Name</TableCell>
            <TableCell>Status</TableCell>
            <TableCell>Progress</TableCell>
            <TableCell>Actions</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {scans.map((scan) => (
            <TableRow key={scan.id}>
              <TableCell>{scan.name}</TableCell>
              <TableCell>{scan.status}</TableCell>
              <TableCell sx={{ width: 200 }}>
                <LinearProgress variant="determinate" value={scan.progress} />
                <Typography variant="caption">{scan.progress}%</Typography>
              </TableCell>
              <TableCell>
                {/* Buttons as before */}
                <Button variant="contained" size="small" sx={{ mr: 1 }} onClick={() => handleRunScan(scan.id)}>RUN</Button>
                <Button variant="outlined" color="error" size="small" sx={{ mr: 1 }} onClick={() => handleCancelScan(scan.id)}>CANCEL</Button>
                <Button variant="contained" color="secondary" size="small" sx={{ mr: 1 }} onClick={() => handleViewDetails(scan.id)}>DETAILS</Button>
                <Button variant="outlined" color="warning" size="small" sx={{ mr: 1 }} onClick={() => handleEdit(scan.id)}>EDIT</Button>
                <Button variant="outlined" color="error" size="small" onClick={() => handleDelete(scan.id)}>DELETE</Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  </div>
</Container>
  );
};

export default DashboardPage;
