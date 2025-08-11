import React from 'react';
import Lottie from 'lottie-react';
import animationData from '../assets/Animation-1745679716062.json';
import { Container, Typography,Link , Paper, Box } from '@mui/material';

const HomePage = () => {
  return (
    <Container sx={{ minHeight: '80vh', display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center' }}>
      <Box sx={{ width: 300, mb: 4 }}>
        <Lottie animationData={animationData} loop autoplay />
      </Box>
      <Paper elevation={4} sx={{ p: 3, textAlign: 'center', backgroundColor: '#f5f5f5' }}>
        <Typography variant="h5" gutterBottom>
        NetScan: Web-based Network Scanner
        </Typography>
        

        <Typography>
  This project was developed by <Box component="span" fontWeight="bold">Mahdi Salmani</Box> for the Master's Web Development course, Programmable Web.
  <br />
  Under the supervision of the course staff: <Box component="span" fontWeight="bold">Iván Sánchez Milara</Box> and <Box component="span" fontWeight="bold">Mika Oja</Box>.
</Typography>
        <Link 
          href="https://github.com/mehdismi/network_scanner" 
          target="_blank" 
          underline="hover" 
          sx={{ display: 'block', mt: 2 }}
        >
          View on GitHub
        </Link>
        <Link 
          href="https://lovelace.oulu.fi/ohjelmoitava-web/ohjelmoitava-web/" 
          target="_blank" 
          underline="hover" 
          sx={{ display: 'block', mt: 2 }}
        >
          Course Web Page
        </Link>
      </Paper>
    </Container>
  );
};

export default HomePage;
