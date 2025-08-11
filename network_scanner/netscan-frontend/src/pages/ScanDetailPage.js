import ReactApexChart from 'react-apexcharts';

import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import axiosInstance from '../api/axiosInstance';
import {
  Container,
  Typography,
  Paper,
  Box,
  LinearProgress,
  Button,
  List,
  ListItem,
  ListItemText
} from '@mui/material';

const ScanDetailPage = () => {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchScan = async () => {
    try {
      const response = await axiosInstance.get(`scans/${id}/`);
      setScan(response.data);
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch scan details', error);
    }
  };

  useEffect(() => {
    fetchScan();

    const interval = setInterval(() => {
      fetchScan();
    }, 5000);

    return () => clearInterval(interval);
  }, [id]);

  if (loading || !scan) return <div>Loading...</div>;

  let openPorts = [];
  let services = [];
  let upHosts = 0;

  try {
    const hosts = scan.result?.nmaprun?.host || [];
    const hostsArray = Array.isArray(hosts) ? hosts : [hosts];

    hostsArray.forEach((host) => {
      const ports = host?.ports?.port || [];
      const portsArray = Array.isArray(ports) ? ports : [ports];

      portsArray.forEach((port) => {
        if (port?.state?.['@state'] === 'open') {
          openPorts.push(port['@portid']);
          if (port?.service?.['@name']) {
            services.push(port.service['@name']);
          }
        }
      });
    });

    upHosts = parseInt(scan.result?.nmaprun?.runstats?.hosts?.['@up'] || 0);
  } catch (error) {
    console.error('Error parsing scan result', error);
  }

  return (
    <Container sx={{ mt: 4 }}>
      <Typography variant="h4" gutterBottom>Scan Details</Typography>
      <Typography variant="subtitle1" color="textSecondary">Scan ID: {id}</Typography>

    
      <Paper elevation={3} sx={{ p: 4, mb: 4 }}>
        <Typography variant="h6">Name: {scan.name}</Typography>
        <Typography>Description: {scan.description}</Typography>
        <Typography>Target: {scan.target}</Typography>
        <Typography>Status: {scan.status}</Typography>
        <Box sx={{ mt: 2 }}>
          <Typography variant="subtitle1">Progress</Typography>
          <LinearProgress variant="determinate" value={scan.progress} />
          <Typography variant="caption">{scan.progress}%</Typography>
        </Box>
      </Paper>
    
      <Paper elevation={3} sx={{ p: 4, mb: 4 }}>
        <Typography variant="h6" gutterBottom>Open Ports (Chart)</Typography>

        <ReactApexChart
            options={{
            chart: {
                type: 'bar'
            },
            xaxis: {
                categories: openPorts.map((port) => `Port ${port}`)
            }
            }}
            series={[
            {
                name: 'Open Ports',
                data: openPorts.map(() => 1)
            }
            ]}
            type="bar"
            height={300}
        />
    </Paper>


    {/*
      <Paper elevation={3} sx={{ p: 4, mb: 4 }}>
        <Typography variant="h6" gutterBottom>Open Ports</Typography>
        {openPorts.length === 0 ? (
          <Typography>No open ports detected.</Typography>
        ) : (
          <List>
            {openPorts.map((port, index) => (
              <ListItem key={index}>
                <ListItemText primary={`Port: ${port}`} />
              </ListItem>
            ))}
          </List>
        )}
      </Paper>
      */}
{/*
      <Paper elevation={3} sx={{ p: 4, mb: 4 }}>
        <Typography variant="h6" gutterBottom>Services</Typography>
        {services.length === 0 ? (
          <Typography>No services detected.</Typography>
        ) : (
          <List>
            {services.map((service, index) => (
              <ListItem key={index}>
                <ListItemText primary={service} />
              </ListItem>
            ))}
          </List>
        )}
      </Paper>
      */}
      <Paper elevation={3} sx={{ p: 4, mb: 4 }}>
        <Typography variant="h6" gutterBottom>Services Distribution (Pie Chart)</Typography>

        <ReactApexChart
            options={{
            labels: services.length ? services : ['No Services'],
            chart: {
                type: 'pie'
            },
            colors: ['#00E396', '#008FFB', '#FEB019', '#FF4560', '#775DD0'],
            legend: {
                position: 'bottom'
            }
            }}
            series={services.length ? services.map(() => 1) : [1]}
            type="pie"
            height={300}
        />
    </Paper>

        {/*
      <Paper elevation={3} sx={{ p: 4 }}>
        <Typography variant="h6">Hosts Up: {upHosts}</Typography>
      </Paper>
      */}
      <Paper elevation={3} sx={{ p: 4, mb: 4 }}>
        <Typography variant="h6" gutterBottom>Hosts Up/Down (Doughnut Chart)</Typography>

        <ReactApexChart
            options={{
            labels: ['Hosts Up', 'Hosts Down'],
            chart: {
                type: 'donut'
            },
            colors: ['#00E396', '#FF4560'],
            legend: {
                position: 'bottom'
            }
            }}
            series={[upHosts, Math.max(0, (parseInt(scan.result?.nmaprun?.runstats?.hosts?.['@total'] || 0) - upHosts))]}
            type="donut"
            height={300}
        />
    </Paper>

    </Container>
  );
};

export default ScanDetailPage;
