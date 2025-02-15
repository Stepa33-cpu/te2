import { useState, useRef, useEffect } from 'react';
import {
    LogOut,
    FolderOpen,
    Link,
    BarChart2,
    Settings,
    Download,
    Eye,
    Search,
    Filter,
    Trash2,
    Share2,
    FileText,
    FileArchive,
    SortAsc,
    MoreVertical,
    FolderPlus,
    Upload,
    CheckCircle,
} from 'lucide-react';
import {
    LineChart,
    Line,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
} from 'recharts';
import { useAuth } from '../contexts/AuthContext';
import logo from '../assets/images/lexchain_logo.png';

const Dashboard = () => {
    const { logout, user } = useAuth();
    const [activeTab, setActiveTab] = useState('files');
    const [myFilesPassword, setMyFilesPassword] = useState('');
    const [selectedFile, setSelectedFile] = useState(null);
    const [lastUploadedFile, setLastUploadedFile] = useState(null);
    const [logs, setLogs] = useState([]);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState(null);

    const mockStorageData = [
        { name: 'Jan', usage: 65 },
        { name: 'Feb', usage: 72 },
        { name: 'Mar', usage: 78 },
        { name: 'Apr', usage: 85 },
        { name: 'May', usage: 82 },
    ];

    const navItems = [
        { id: 'files', icon: <FolderOpen size={20} />, label: 'File Management' },
        { id: 'myfiles', icon: <FileText size={20} />, label: 'My Files' },
        { id: 'blockchain', icon: <Link size={20} />, label: 'Blockchain Verification' },
        { id: 'monitor', icon: <BarChart2 size={20} />, label: 'System Monitoring' },
        { id: 'settings', icon: <Settings size={20} />, label: 'Settings' },
    ];

    const FileManagement = () => {
        const fileInputRef = useRef(null);
        const [isUploading, setIsUploading] = useState(false);
        const [uploadStatus, setUploadStatus] = useState('');
        const [fileMasterPassword, setFileMasterPassword] = useState('');
        const [uploadResult, setUploadResult] = useState(null);

        const handleFileSelect = (event) => {
            const file = event.target.files[0];
            if (file) {
                setSelectedFile(file);
                setUploadStatus('');
                setUploadResult(null);
                setLastUploadedFile(null);
            }
        };

        const handleDragOver = (event) => {
            event.preventDefault();
        };

        const handleDrop = (event) => {
            event.preventDefault();
            const file = event.dataTransfer.files[0];
            if (file) {
                setSelectedFile(file);
                setUploadStatus('');
                setUploadResult(null);
                setLastUploadedFile(null);
            }
        };

        const openFileDialog = () => {
            fileInputRef.current.click();
        };

        const handleFileUpload = async () => {
            if (!selectedFile || !fileMasterPassword) {
                setUploadResult({
                    success: false,
                    message: "Please select a file and enter the master password."
                });
                setLastUploadedFile({
                    name: selectedFile?.name || 'Unknown',
                    date: new Date().toISOString().split('T')[0],
                    size: selectedFile ? (selectedFile.size / (1024 * 1024)).toFixed(2) : 0,
                    status: 'Failed - Missing Password'
                });
                return;
            }

            const formData = new FormData();
            formData.append("file", selectedFile);
            formData.append("password", fileMasterPassword);

            setIsUploading(true);
            setUploadResult(null);

            // Set uploading status immediately
            setLastUploadedFile({
                name: selectedFile.name,
                date: new Date().toISOString().split('T')[0],
                size: (selectedFile.size / (1024 * 1024)).toFixed(2),
                status: 'Uploading...'
            });

            try {
                const response = await fetch("http://localhost:5000/upload", {
                    method: "POST",
                    body: formData,
                    credentials: 'include',
                });

                const data = await response.json();

                if (!response.ok) {
                    if (response.status === 401 && data.redirect) {
                        // Session expired, redirect to login
                        window.location.href = 'http://localhost:5000/login';
                        return;
                    }
                    throw new Error(data.error || `Upload failed: ${response.statusText}`);
                }

                // Update status but keep the file info
                setLastUploadedFile(prev => ({
                    ...prev,
                    status: 'Upload Successful',
                    fileId: data.file_id
                }));

                setUploadResult({
                    success: true,
                    message: "File uploaded successfully!",
                    fileId: data.file_id
                });

                // Only clear the form inputs
                setSelectedFile(null);
                setFileMasterPassword('');
            } catch (error) {
                console.error("Error during file upload:", error);
                // Update status but keep the file info
                setLastUploadedFile(prev => ({
                    ...prev,
                    status: 'Upload Failed'
                }));
                setUploadResult({
                    success: false,
                    message: error.message || "An error occurred while uploading the file."
                });
            } finally {
                setIsUploading(false);
            }
        };

        return (
            <div className="h-full p-6 space-y-6">
                <div className="bg-white rounded-lg p-6 border border-gray-200 shadow-sm">
                    <input
                        type="file"
                        ref={fileInputRef}
                        onChange={handleFileSelect}
                        className="hidden"
                    />
                    <div
                        className="border-2 border-dashed border-blue-200 rounded-lg p-8 text-center cursor-pointer hover:border-blue-300 hover:bg-blue-50 transition-colors"
                        onClick={openFileDialog}
                        onDragOver={handleDragOver}
                        onDrop={handleDrop}
                    >
                        <Upload className="mx-auto mb-4 text-blue-500" size={32} />
                        <p className="text-gray-600 mb-2">
                            {selectedFile
                                ? `Selected: ${selectedFile.name}`
                                : 'Drag and drop files here or click to upload'
                            }
                        </p>
                        {uploadStatus && (
                            <p className={`text-sm mt-2 ${
                                uploadStatus.includes('error') || uploadStatus.includes('Please') 
                                    ? 'text-red-500' 
                                    : uploadStatus.includes('successful') 
                                        ? 'text-green-500' 
                                        : 'text-blue-500'
                            }`}>
                                {uploadStatus}
                            </p>
                        )}
                    </div>

                    {uploadResult && (
                        <div className={`mt-4 p-4 rounded-lg ${
                            uploadResult.success ? 'bg-green-50 border border-green-200' : 'bg-red-50 border border-red-200'
                        }`}>
                            <p className={`font-medium ${
                                uploadResult.success ? 'text-green-700' : 'text-red-700'
                            }`}>
                                {uploadResult.message}
                            </p>
                            {uploadResult.fileId && (
                                <p className="text-sm mt-1 text-green-600">
                                    File ID: {uploadResult.fileId}
                                </p>
                            )}
                        </div>
                    )}

                    <div className="mt-4 flex items-center justify-center space-x-4">
                        <input
                            type="password"
                            placeholder="Master Password"
                            className="px-4 py-2 border border-gray-200 rounded-lg w-64"
                            value={fileMasterPassword}
                            onChange={(e) => setFileMasterPassword(e.target.value)}
                        />
                        <button
                            onClick={handleFileUpload}
                            disabled={isUploading}
                            className={`px-4 py-2 bg-gradient-to-r from-blue-600 to-blue-500 text-white rounded-lg hover:from-blue-700 hover:to-blue-600 inline-flex items-center space-x-2 ${
                                isUploading ? 'opacity-50 cursor-not-allowed' : ''
                            }`}
                        >
                            {isUploading ? (
                                <>
                                    <div className="animate-spin rounded-full h-5 w-5 border-2 border-white border-t-transparent"></div>
                                    <span>Uploading...</span>
                                </>
                            ) : (
                                <>
                                    <CheckCircle size={20} />
                                    <span>Confirm</span>
                                </>
                            )}
                        </button>
                    </div>
                </div>

                <div className="bg-white rounded-lg p-6 border border-gray-200 shadow-sm">
                    <h3 className="text-xl font-semibold mb-4 text-gray-800">Last Upload Status</h3>
                    <table className="w-full">
                        <thead>
                            <tr className="text-left border-b border-gray-200">
                                <th className="pb-3 text-gray-600">Name</th>
                                <th className="pb-3 text-gray-600">Date</th>
                                <th className="pb-3 text-gray-600">Size</th>
                                <th className="pb-3 text-gray-600">Status</th>
                                <th className="pb-3 text-gray-600">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {!lastUploadedFile ? (
                                <tr>
                                    <td colSpan="5" className="py-4 text-center text-gray-500">
                                        No files uploaded yet
                                    </td>
                                </tr>
                            ) : (
                                <tr className="border-b border-gray-100">
                                    <td className="py-3 text-gray-700">{lastUploadedFile.name}</td>
                                    <td className="text-gray-600">{lastUploadedFile.date}</td>
                                    <td className="text-gray-600">{lastUploadedFile.size} MB</td>
                                    <td>
                                        <span className={`px-2 py-1 rounded-full text-sm ${
                                            lastUploadedFile.status === 'Upload Successful' 
                                                ? 'bg-green-100 text-green-700'
                                                : lastUploadedFile.status === 'Uploading...'
                                                    ? 'bg-blue-100 text-blue-700'
                                                    : 'bg-red-100 text-red-700'
                                        }`}>
                                            {lastUploadedFile.status}
                                        </span>
                                    </td>
                                    <td className="space-x-2">
                                        <button 
                                            className={`p-1 bg-gradient-to-r from-blue-600 to-blue-500 text-white rounded-lg hover:from-blue-700 hover:to-blue-600 ${
                                                lastUploadedFile.status !== 'Upload Successful' ? 'opacity-50 cursor-not-allowed' : ''
                                            }`}
                                            disabled={lastUploadedFile.status !== 'Upload Successful'}
                                        >
                                            <Download size={16} />
                                        </button>
                                        <button 
                                            className={`p-1 bg-gradient-to-r from-blue-600 to-blue-500 text-white rounded-lg hover:from-blue-700 hover:to-blue-600 ${
                                                lastUploadedFile.status !== 'Upload Successful' ? 'opacity-50 cursor-not-allowed' : ''
                                            }`}
                                            disabled={lastUploadedFile.status !== 'Upload Successful'}
                                        >
                                            <Eye size={16} />
                                        </button>
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        );
    };

    const MyFiles = () => {
        const [searchTerm, setSearchTerm] = useState('');
        const [myFilesPassword, setMyFilesPassword] = useState('');
        const [files, setFiles] = useState([]);
        const [isLoading, setIsLoading] = useState(false);
        const [error, setError] = useState(null);
        const [downloadingFileId, setDownloadingFileId] = useState(null);
        const [deletingFileId, setDeletingFileId] = useState(null);

        const handleShowFiles = async () => {
            if (!myFilesPassword) {
                setError("Please enter the master password");
                return;
            }

            setIsLoading(true);
            setError(null);

            try {
                const response = await fetch("http://localhost:5000/api/files/filtered", {
                    method: "POST",
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    body: JSON.stringify({
                        password: myFilesPassword
                    })
                });

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.error || "Failed to fetch files");
                }

                console.log(`Found ${data.total_count} files`);
                setFiles(data.files);
                
                if (data.files.length === 0) {
                    setError("No files found encrypted with this password");
                }
            } catch (error) {
                console.error("Error fetching files:", error);
                setError(error.message || "Failed to load files");
            } finally {
                setIsLoading(false);
            }
        };

        const handleDownload = async (fileId, fileName) => {
            if (!myFilesPassword) {
                setError("Please enter the master password to download files");
                return;
            }

            setDownloadingFileId(fileId);
            setError(null);

            try {
                const response = await fetch("http://localhost:5000/download", {
                    method: "POST",
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        file_id: fileId,
                        password: myFilesPassword
                    })
                });

                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.error || "Failed to download file");
                }

                // Get the blob from the response
                const blob = await response.blob();
                
                // Create a download link
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = fileName; // Use the original filename
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);

            } catch (error) {
                console.error("Error downloading file:", error);
                setError(error.message || "Failed to download file");
            } finally {
                setDownloadingFileId(null);
            }
        };

        const handleDelete = async (fileId, fileName) => {
            if (!myFilesPassword) {
                setError("Please enter the master password to delete files");
                return;
            }

            if (!window.confirm(`Are you sure you want to delete "${fileName}"?`)) {
                return;
            }

            setDeletingFileId(fileId);
            setError(null);

            try {
                const response = await fetch("http://localhost:5000/delete", {
                    method: "POST",
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        file_id: fileId,
                        password: myFilesPassword
                    })
                });

                const data = await response.json();
                if (!response.ok) {
                    throw new Error(data.error || "Failed to delete file");
                }

                // Remove the deleted file from the files list
                setFiles(prevFiles => prevFiles.filter(file => file.id !== fileId));

            } catch (error) {
                console.error("Error deleting file:", error);
                setError(error.message || "Failed to delete file");
            } finally {
                setDeletingFileId(null);
            }
        };

        return (
            <div className="p-6 space-y-6">
                <div className="flex justify-between items-center">
                    <h1 className="text-2xl font-bold text-gray-800">My Files</h1>
                </div>

                <div className="flex space-x-4">
                    <div className="flex-1 relative">
                        <Search className="absolute left-3 top-2.5 text-gray-400" size={20} />
                        <input
                            type="text"
                            placeholder="Search files..."
                            className="w-full bg-white border border-gray-200 rounded-lg pl-10 pr-4 py-2 text-gray-700"
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                        />
                    </div>
                    <div className="flex space-x-2">
                        <input
                            type="password"
                            placeholder="Master Password"
                            className="w-64 px-4 py-2 border border-gray-200 rounded-lg"
                            value={myFilesPassword}
                            onChange={(e) => setMyFilesPassword(e.target.value)}
                        />
                        <button
                            onClick={handleShowFiles}
                            disabled={isLoading}
                            className="flex items-center space-x-2 px-4 py-2 bg-gradient-to-r from-blue-600 to-blue-500 text-white rounded-lg hover:from-blue-700 hover:to-blue-600 disabled:opacity-50"
                        >
                            {isLoading ? (
                                <>
                                    <div className="animate-spin rounded-full h-5 w-5 border-2 border-white border-t-transparent"></div>
                                    <span>Loading...</span>
                                </>
                            ) : (
                                <>
                                    <Eye size={20} />
                                    <span>Show Files</span>
                                </>
                            )}
                        </button>
                    </div>
                </div>

                {error && (
                    <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg">
                        {error}
                    </div>
                )}

                <div className="bg-white rounded-lg border border-gray-200 shadow-sm">
                    <table className="w-full">
                        <thead>
                            <tr className="border-b border-gray-200">
                                <th className="text-left p-4 text-gray-600">Name</th>
                                <th className="text-left p-4 text-gray-600">Size</th>
                                <th className="text-left p-4 text-gray-600">Modified</th>
                                <th className="text-left p-4 text-gray-600">Status</th>
                                <th className="text-right p-4 text-gray-600">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {files.length === 0 ? (
                                <tr>
                                    <td colSpan="5" className="text-center py-8 text-gray-500">
                                        {isLoading ? 'Loading files...' : 'No files found'}
                                    </td>
                                </tr>
                            ) : (
                                files.map((file) => (
                                    <tr key={file.id} className="border-b border-gray-100 hover:bg-gray-50">
                                        <td className="p-4">
                                            <div className="flex items-center space-x-3">
                                                <FileText className="text-blue-600" size={20} />
                                                <span className="text-gray-700">{file.name}</span>
                                            </div>
                                        </td>
                                        <td className="p-4 text-gray-600">
                                            {(file.size / (1024 * 1024)).toFixed(2)} MB
                                        </td>
                                        <td className="p-4 text-gray-600">{file.date}</td>
                                        <td className="p-4">
                                            <span className="px-2 py-1 bg-green-100 text-green-700 rounded-full text-sm">
                                                {file.status}
                                            </span>
                                        </td>
                                        <td className="p-4">
                                            <div className="flex items-center justify-end space-x-2">
                                                <button 
                                                    onClick={() => handleDownload(file.id, file.name)}
                                                    disabled={downloadingFileId === file.id}
                                                    className="p-2 bg-gradient-to-r from-blue-600 to-blue-500 text-white rounded-lg hover:from-blue-700 hover:to-blue-600 disabled:opacity-50"
                                                >
                                                    {downloadingFileId === file.id ? (
                                                        <div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent" />
                                                    ) : (
                                                        <Download size={18} />
                                                    )}
                                                </button>
                                                <button 
                                                    onClick={() => handleDelete(file.id, file.name)}
                                                    disabled={deletingFileId === file.id}
                                                    className="p-2 bg-gradient-to-r from-blue-600 to-blue-500 text-white rounded-lg hover:from-blue-700 hover:to-blue-600 disabled:opacity-50"
                                                >
                                                    {deletingFileId === file.id ? (
                                                        <div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent" />
                                                    ) : (
                                                        <Trash2 size={18} />
                                                    )}
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        );
    };

    const BlockchainVerification = () => {
        const [masterPassword, setMasterPassword] = useState('');
        const [blockchainLogs, setBlockchainLogs] = useState([]);
        const [isLoading, setIsLoading] = useState(false);
        const [error, setError] = useState(null);

        const fetchBlockchainLogs = async () => {
            if (!masterPassword) {
                setError('Please enter the master password');
                return;
            }
            
            setIsLoading(true);
            setError('');
            
            try {
                const response = await fetch('http://localhost:5000/api/blockchain/logs', {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ password: masterPassword })
                });

                const text = await response.text();
                let data;
                try {
                    data = JSON.parse(text);
                } catch (err) {
                    console.error('Failed to parse response:', text);
                    throw new Error('Invalid response from server');
                }

                if (!response.ok) {
                    throw new Error(data.error || 'Failed to fetch logs');
                }

                setBlockchainLogs(data.logs || []);
            } catch (error) {
                console.error('Error fetching blockchain logs:', error);
                setError(error.message);
            } finally {
                setIsLoading(false);
            }
        };

        const formatDate = (timestamp) => {
            const date = new Date(timestamp);
            return date.toLocaleString();
        };

        const getActionColor = (action) => {
            switch (action.toLowerCase()) {
                case 'upload':
                    return 'text-green-600 bg-green-100';
                case 'download':
                    return 'text-blue-600 bg-blue-100';
                case 'delete':
                    return 'text-red-600 bg-red-100';
                default:
                    return 'text-gray-600 bg-gray-100';
            }
        };

        return (
            <div className="h-full p-6 space-y-6">
                <div className="bg-white rounded-lg p-6 border border-gray-200 shadow-sm">
                    <div className="flex justify-between items-center mb-6">
                        <h3 className="text-xl font-semibold text-gray-800">Blockchain Activity Log</h3>
                        <div className="flex items-center gap-4">
                            <input
                                type="password"
                                placeholder="Enter Master Password"
                                value={masterPassword}
                                onChange={(e) => setMasterPassword(e.target.value)}
                                className="px-4 py-2 border border-gray-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                            />
                            <button
                                onClick={fetchBlockchainLogs}
                                disabled={isLoading}
                                className="px-4 py-2 bg-gradient-to-r from-blue-600 to-blue-500 text-white rounded-lg hover:from-blue-700 hover:to-blue-600 disabled:opacity-50 flex items-center gap-2"
                            >
                                {isLoading ? (
                                    <>
                                        <div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent"></div>
                                        <span>Loading...</span>
                                    </>
                                ) : (
                                    'View Logs'
                                )}
                            </button>
                        </div>
                    </div>

                    {error && (
                        <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">
                            {error}
                        </div>
                    )}

                    <div className="space-y-4">
                        {blockchainLogs.length === 0 ? (
                            <div className="text-center text-gray-500 mt-4">
                                {isLoading ? 'Loading logs...' : 'Enter master password and click View Logs to see blockchain activity'}
                            </div>
                        ) : (
                            <div className="space-y-4">
                                {blockchainLogs.map((log, index) => (
                                    <div
                                        key={index}
                                        className="p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors"
                                    >
                                        <div className="flex items-center justify-between mb-2">
                                            <span className={`px-3 py-1 rounded-full text-sm font-medium ${getActionColor(log.action)}`}>
                                                {log.action.toUpperCase()}
                                            </span>
                                            <span className="text-sm text-gray-500">
                                                {formatDate(log.timestamp)}
                                            </span>
                                        </div>
                                        <div className="text-gray-700">
                                            <div className="font-medium">File ID: {log.details.file_id}</div>
                                            {log.details.filename && (
                                                <div className="text-sm text-gray-600">
                                                    Filename: {log.details.filename}
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
            </div>
        );
    };

    const SystemMonitoring = () => (
        <div className="h-full p-6 space-y-6">
            <div className="bg-white rounded-lg p-6 border border-gray-200 shadow-sm">
                <h3 className="text-xl font-semibold mb-4 text-gray-800">Storage Usage</h3>
                <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={mockStorageData}>
                            <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,0,0,0.1)" />
                            <XAxis dataKey="name" stroke="rgba(0,0,0,0.5)" />
                            <YAxis stroke="rgba(0,0,0,0.5)" />
                            <Tooltip
                                contentStyle={{
                                    backgroundColor: 'white',
                                    border: '1px solid #e5e7eb',
                                }}
                            />
                            <Line type="monotone" dataKey="usage" stroke="#1e40af" />
                        </LineChart>
                    </ResponsiveContainer>
                </div>
            </div>

            <div className="grid grid-cols-2 gap-6">
                <div className="bg-white rounded-lg p-6 border border-gray-200 shadow-sm">
                    <h3 className="text-xl font-semibold mb-4 text-gray-800">Sharding Status</h3>
                    <div className="space-y-4">
                        <div>
                            <div className="flex justify-between mb-2">
                                <span className="text-gray-700">Primary Shard</span>
                                <span className="text-gray-600">98%</span>
                            </div>
                            <div className="w-full bg-gray-100 rounded-full h-2">
                                <div className="bg-green-500 h-2 rounded-full" style={{ width: '98%' }}></div>
                            </div>
                        </div>
                        <div>
                            <div className="flex justify-between mb-2">
                                <span className="text-gray-700">Backup Shard</span>
                                <span className="text-gray-600">85%</span>
                            </div>
                            <div className="w-full bg-gray-100 rounded-full h-2">
                                <div className="bg-blue-500 h-2 rounded-full" style={{ width: '85%' }}></div>
                            </div>
                        </div>
                    </div>
                </div>

                <div className="bg-white rounded-lg p-6 border border-gray-200 shadow-sm">
                    <h3 className="text-xl font-semibold mb-4 text-gray-800">Encryption Status</h3>
                    <div className="space-y-4">
                        <div className="flex items-center justify-between p-3 border border-gray-200 rounded-lg">
                            <span className="text-gray-700">AES-256 Encryption</span>
                            <span className="px-2 py-1 bg-green-100 text-green-700 rounded-full text-sm">Active</span>
                        </div>
                        <div className="flex items-center justify-between p-3 border border-gray-200 rounded-lg">
                            <span className="text-gray-700">Key Rotation</span>
                            <span className="px-2 py-1 bg-blue-100 text-blue-700 rounded-full text-sm">Scheduled</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );

    const SettingsPage = () => (
        <div className="h-full p-6 space-y-6">
            <div className="bg-white rounded-lg p-6 border border-gray-200 shadow-sm">
                <h3 className="text-xl font-semibold mb-4 text-gray-800">Encryption Settings</h3>
                <div className="space-y-4">
                    <div>
                        <label className="block mb-2 text-gray-700">Encryption Level</label>
                        <select className="w-full bg-gray-50 border border-gray-200 rounded-lg px-4 py-2 text-gray-700">
                            <option>AES-256 (Recommended)</option>
                            <option>AES-192</option>
                            <option>AES-128</option>
                        </select>
                    </div>
                    <div>
                        <label className="block mb-2 text-gray-700">Key Rotation Interval</label>
                        <select className="w-full bg-gray-50 border border-gray-200 rounded-lg px-4 py-2 text-gray-700">
                            <option>30 Days</option>
                            <option>60 Days</option>
                            <option>90 Days</option>
                        </select>
                    </div>
                </div>
            </div>

            <div className="bg-white rounded-lg p-6 border border-gray-200 shadow-sm">
                <h3 className="text-xl font-semibold mb-4 text-gray-800">OneDrive API Configuration</h3>
                <div className="space-y-4">
                    <div>
                        <label className="block mb-2 text-gray-700">API Key</label>
                        <input
                            type="password"
                            value="••••••••••••••••"
                            className="w-full bg-gray-50 border border-gray-200 rounded-lg px-4 py-2 text-gray-700"
                        />
                    </div>
                    <div>
                        <label className="block mb-2 text-gray-700">API Endpoint</label>
                        <input
                            type="text"
                            value="https://api.onedrive.com/v1.0/"
                            className="w-full bg-gray-50 border border-gray-200 rounded-lg px-4 py-2 text-gray-700"
                        />
                    </div>
                </div>
            </div>

            <div className="bg-white rounded-lg p-6 border border-gray-200 shadow-sm">
                <h3 className="text-xl font-semibold mb-4 text-gray-800">Preferences</h3>
                <div className="space-y-4">
                    <div className="flex items-center justify-between p-3 border border-gray-200 rounded-lg">
                        <span className="text-gray-700">Dark Mode</span>
                        <div className="w-12 h-6 bg-blue-600 rounded-full relative">
                            <div className="absolute right-1 top-1 w-4 h-4 bg-white rounded-full"></div>
                        </div>
                    </div>
                    <div className="flex items-center justify-between p-3 border border-gray-200 rounded-lg">
                        <span className="text-gray-700">Email Notifications</span>
                        <div className="w-12 h-6 bg-gray-200 rounded-full relative">
                            <div className="absolute left-1 top-1 w-4 h-4 bg-white rounded-full"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );

    return (
        <div className="w-screen h-screen overflow-hidden bg-gradient-to-br from-blue-50 via-blue-50 to-white text-gray-800 relative">
            {/* Background effects */}
            <div className="absolute inset-0 overflow-hidden pointer-events-none">
                {/* Animated gradient background */}
                <div className="absolute inset-0 bg-gradient-to-r from-blue-100/40 via-blue-50/30 to-blue-100/40 animate-gradient-x"></div>
                
                {/* Floating particles */}
                <div className="absolute inset-0">
                    <div className="absolute h-32 w-32 rounded-full bg-blue-100/50 -top-16 -left-16 animate-float-slow"></div>
                    <div className="absolute h-40 w-40 rounded-full bg-blue-50/50 bottom-1/4 left-1/3 animate-float-fast"></div>
                </div>
            </div>

            {/* Main content */}
            <div className="w-full h-full flex relative z-10">
                <div className="h-full w-64 flex-shrink-0 bg-gradient-to-b from-blue-950 to-blue-900 flex flex-col">
                    <div className="px-6 py-5">
                        <h1 className="text-2xl font-semibold text-white tracking-wide">
                            LexChain
                        </h1>
                    </div>

                    <div className="flex items-center gap-3 px-4 py-6 border-b border-blue-800/30">
                        <div className="w-10 h-10 rounded-full bg-blue-800/40 flex items-center justify-center">
                            <span className="text-white text-lg">
                                {user?.name?.[0] || 'U'}
                            </span>
                        </div>
                        <div className="text-white/90">
                            <div className="text-sm opacity-70">Hey,</div>
                            <div className="text-base font-medium">
                                {user?.name || 'User'}
                            </div>
                        </div>
                    </div>

                    <nav className="flex-1 px-3 mt-6 space-y-1.5">
                        {navItems.map((item) => (
                            <button
                                key={item.id}
                                onClick={() => setActiveTab(item.id)}
                                className={`w-full flex items-center gap-3 px-4 py-2.5 rounded-lg transition-all duration-200 ${
                                    activeTab === item.id
                                        ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20'
                                        : 'text-white/70 hover:bg-white/10 hover:text-white'
                                }`}
                            >
                                <span className={`${activeTab === item.id ? 'opacity-100' : 'opacity-70'}`}>
                                    {item.icon}
                                </span>
                                <span className="text-sm font-medium whitespace-nowrap">
                                    {item.label}
                                </span>
                            </button>
                        ))}
                    </nav>

                    <div className="p-3 mt-auto">
                        <button
                            onClick={logout}
                            className="w-full flex items-center gap-3 px-4 py-2.5 text-white/70 hover:bg-white/10 hover:text-white rounded-lg transition-colors"
                        >
                            <span className="opacity-70">
                                <LogOut size={20} />
                            </span>
                            <span className="text-sm font-medium">Sign Out</span>
                        </button>
                    </div>
                </div>

                <div className="flex-1 h-full w-full overflow-hidden bg-white/80 backdrop-blur-sm">
                    <div className="h-full w-full overflow-auto">
                        {activeTab === 'files' && <FileManagement />}
                        {activeTab === 'myfiles' && <MyFiles />}
                        {activeTab === 'blockchain' && <BlockchainVerification />}
                        {activeTab === 'monitor' && <SystemMonitoring />}
                        {activeTab === 'settings' && <SettingsPage />}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Dashboard; 