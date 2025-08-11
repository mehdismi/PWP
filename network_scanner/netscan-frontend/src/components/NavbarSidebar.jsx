import React, { useState, useContext } from 'react';
import { Drawer, List, ListItem, ListItemIcon, ListItemText, IconButton, Box, Toolbar, Typography } from '@mui/material';
import MenuIcon from '@mui/icons-material/Menu';
import DashboardIcon from '@mui/icons-material/Dashboard';
import AddBoxIcon from '@mui/icons-material/AddBox';
import AccountCircleIcon from '@mui/icons-material/AccountCircle';
import TimelineIcon from '@mui/icons-material/Timeline';
import ExitToAppIcon from '@mui/icons-material/ExitToApp';
import LoginIcon from '@mui/icons-material/Login';
import PersonAddIcon from '@mui/icons-material/PersonAdd';
import { Link, useNavigate } from 'react-router-dom';
import AuthContext from '../auth/AuthContext';

const NavbarSidebar = () => {
  const [open, setOpen] = useState(false);
  const { user, logout } = useContext(AuthContext);
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/');
  };

  const loggedInItems = [
    { text: 'Dashboard', icon: <DashboardIcon />, path: '/v1/dashboard' },
    { text: 'Create Scan', icon: <AddBoxIcon />, path: '/v1/create-scan' },
    { text: 'Activity', icon: <TimelineIcon />, path: '/v1/activity' },
    { text: 'Profile', icon: <AccountCircleIcon />, path: `/v1/profile/${user?.id}` },
    { text: 'Logout', icon: <ExitToAppIcon />, action: handleLogout }
  ];

  const loggedOutItems = [
    { text: 'Login', icon: <LoginIcon />, path: '/v1/login' },
    { text: 'Register', icon: <PersonAddIcon />, path: '/v1/register' }
  ];

  return (
    <>
      <Toolbar>
        <IconButton edge="start" color="inherit" aria-label="menu" onClick={() => setOpen(true)}>
        <MenuIcon sx={{ fontSize: 40 }} />
        </IconButton>
      </Toolbar>

      <Drawer anchor="left" open={open} onClose={() => setOpen(false)}>
        <Box sx={{ width: 250 }}>
          <Box sx={{ p: 2, backgroundColor: '#1976d2', color: '#fff', textAlign: 'center', cursor: 'pointer' }}
            onClick={() => {
              navigate('/');
              setOpen(false);
            }}
          >
            <Typography variant="h6">Network Scanner</Typography>
          </Box>

          <List>
            {(user ? loggedInItems : loggedOutItems).map((item, index) => (
              <ListItem
              button
              key={index}
              onClick={() => {
                if (item.path) {
                  navigate(item.path);
                } else if (item.action) {
                  item.action();
                }
                setOpen(false);
              }}
              sx={{
                cursor: 'pointer',
                userSelect: 'none',
                '&:hover': {
                  backgroundColor: '#eeeeee',
                }
              }}
            >
                <ListItemIcon>{item.icon}</ListItemIcon>
                <ListItemText primary={item.text} />
              </ListItem>
            ))}
          </List>
        </Box>
      </Drawer>
    </>
  );
};

export default NavbarSidebar;
