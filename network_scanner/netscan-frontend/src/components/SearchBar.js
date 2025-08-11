import React, { useContext, useState } from 'react';
import { Drawer, List, ListItem, ListItemIcon, ListItemText, IconButton, Box, Toolbar } from '@mui/material';
import MenuIcon from '@mui/icons-material/Menu';
import DashboardIcon from '@mui/icons-material/Dashboard';
import AddBoxIcon from '@mui/icons-material/AddBox';
import AccountCircleIcon from '@mui/icons-material/AccountCircle';
import TimelineIcon from '@mui/icons-material/Timeline';
import ExitToAppIcon from '@mui/icons-material/ExitToApp';
import { Link, useNavigate } from 'react-router-dom';
import AuthContext from '../auth/AuthContext';

const NavbarSidebar = () => {
  const [open, setOpen] = useState(false);
  const { logout } = useContext(AuthContext);
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const menuItems = [
    { text: 'Dashboard', icon: <DashboardIcon />, path: '/dashboard' },
    { text: 'Create Scan', icon: <AddBoxIcon />, path: '/create-scan' },
    { text: 'Activity', icon: <TimelineIcon />, path: '/activity' },
    { text: 'Profile', icon: <AccountCircleIcon />, path: `/profile/${user?.id}` },
    { text: 'Logout', icon: <ExitToAppIcon />, action: handleLogout }
  ];

  return (
    <>
      <Toolbar>
        <IconButton edge="start" color="inherit" aria-label="menu" onClick={() => setOpen(true)}>
          <MenuIcon />
        </IconButton>
      </Toolbar>

      <Drawer anchor="left" open={open} onClose={() => setOpen(false)}>
        <Box sx={{ width: 250 }}>
          <List>
            {menuItems.map((item, index) => (
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
