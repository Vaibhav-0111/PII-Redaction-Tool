import streamlit as st
import os
import tempfile
from pii_redactor import PIIRedactor, DocumentReplacer, RegexDetector, NERDetector, DictionaryDetector

st.set_page_config(page_title="PII Redactor", page_icon="🕵️‍♂️")

st.title("PII Redaction Tool 🕵️‍♂️")
st.write("Upload a DOCX file to redact Personally Identifiable Information (PII).")

uploaded_file = st.file_uploader("Choose a DOCX file", type="docx")

if uploaded_file is not None:
    if st.button("Redact Document"):
        with st.spinner("Redacting..."):
            # Save uploaded file to temp file
            with tempfile.NamedTemporaryFile(delete=False, suffix=".docx") as temp_in:
                temp_in.write(uploaded_file.read())
                temp_in_path = temp_in.name
            
            temp_out_path = temp_in_path.replace(".docx", "_redacted.docx")
            
            try:
                # Initialize redactor (similar to main block in pii_redactor.py)
                redactor = PIIRedactor(temp_in_path)
                redactor.add_detector(RegexDetector())
                try:
                    redactor.add_detector(NERDetector())
                except Exception as e:
                    st.warning("NER Model not found. Falling back to Regex and Dictionary only.")
                redactor.add_detector(DictionaryDetector())
                
                # Process
                full_text = redactor.extract_text()
                entities = redactor.detect_all(full_text)
                replacer = DocumentReplacer()
                replacement_map = replacer.create_replacements(entities)
                redactor.apply_replacements(replacement_map)
                redactor.save(temp_out_path)
                
                st.success("Redaction Complete!")
                
                # Provide download button
                with open(temp_out_path, "rb") as f:
                    st.download_button(
                        label="Download Redacted Document",
                        data=f,
                        file_name="redacted_document.docx",
                        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                    )
            except Exception as e:
                st.error(f"An error occurred: {e}")
            finally:
                # Cleanup
                if os.path.exists(temp_in_path):
                    os.remove(temp_in_path)
                if os.path.exists(temp_out_path):
                    os.remove(temp_out_path)
