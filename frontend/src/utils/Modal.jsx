import React from 'react';
import 'bootstrap/dist/js/bootstrap.bundle.min.js';

export default function Modal({ isOpen, title, message, onConfirm, onClose }) {
  if (!isOpen) return null;

  return (
    <div className="modal show fade d-block" tabIndex="-1" role="dialog" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
      <div className="modal-dialog modal-dialog-centered" role="document" onClick={onClose}>
        <div className="modal-content" onClick={(e) => e.stopPropagation()}>
          <div className="modal-header">
            <h5 className="modal-title">{title || 'Session Expiring'}</h5>
            <button type="button" className="btn-close" onClick={onClose}></button>
          </div>
          <div className="modal-body">
            <p>{message || 'You will be logged out due to inactivity. Do you want to stay logged in?'}</p>
          </div>
          <div className="modal-footer">
            <button type="button" className="btn btn-success" onClick={onConfirm}>Stay Logged In</button>
            <button type="button" className="btn btn-danger" onClick={onClose}>Log Out</button>
          </div>
        </div>
      </div>
    </div>
  );
}
