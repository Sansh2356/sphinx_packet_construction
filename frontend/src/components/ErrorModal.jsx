function ErrorModal({ error, onClose }) {
  if (!error) return null

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <span className="error-icon">!</span>
          <h3>Error</h3>
        </div>
        <p className="modal-body">{error}</p>
        <button className="btn btn-primary" onClick={onClose}>
          Close
        </button>
      </div>
    </div>
  )
}

export default ErrorModal
