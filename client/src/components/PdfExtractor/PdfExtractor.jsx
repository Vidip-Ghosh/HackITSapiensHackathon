const PdfExtractor = () => {
  return (
    <div>
      <input type="file" id="inpFile" />
      <button type="button" id="btnUpload">Upload</button>
      <br /><br />
      <textarea
        id="resultText"
        style="width: 300px; height: 150px"
        placeholder="Your PDF text will appear here..."
      ></textarea>
      <br />
      <input type="text" id="filenameInput" placeholder="Enter filename" />
      <button id="btnDownload" style="display: none">Download</button>
    </div>
  )
}

export default PdfExtractor
