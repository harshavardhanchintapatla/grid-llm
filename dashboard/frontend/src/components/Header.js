import React from 'react';
import './Header.css';

const Header = () => {
  return (
    <header className="header">
      <div className="header-content">
        <div className="logo">
          <div className="logo-icon">🛡️</div>
          <h1>DNP3 Security Operations Center</h1>
        </div>
        <div className="header-status">
          <span className="status-indicator active"></span>
          <span>SDN-LLM Framework Active</span>
        </div>
      </div>
    </header>
  );
};

export default Header;
