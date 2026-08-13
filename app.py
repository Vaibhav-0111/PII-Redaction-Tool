import streamlit as st
import os
import tempfile
import traceback
from pii_redactor import DocumentRedactor, PIIDetector, PIIReplacer

st.set_page_config(page_title="PII Redactor", page_icon="🕵️‍♂️")

st.title("PII Redaction Tool 🕵️‍♂️")
st.write("Upload a DOCX file to redact Personally Identifiable Information (PII).")

uploaded_file = st.file_uploader("Choose a DOCX file", type="docx")

if uploaded_file is not None:
    if st.button("Redact Document"):
        with st.spinner("Redacting..."):
            with tempfile.NamedTemporaryFile(delete=False, suffix=".docx") as temp_in:
                temp_in.write(uploaded_file.read())
                temp_in_path = temp_in.name
            
            temp_out_path = temp_in_path.replace(".docx", "_redacted.docx")
            
            try:
                # Initialize redactor
                redactor = DocumentRedactor(temp_in_path)
                full_text = redactor.get_full_text()
                
                try:
                    detector = PIIDetector(use_ner=True)
                except OSError:
                    st.warning("NER Model not found. Falling back to Regex and Dictionary only.")
                    detector = PIIDetector(use_ner=False)
                
                # Process
                entities = detector.detect_all(full_text)
                replacer = PIIReplacer(seed=42)
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
                st.code(traceback.format_exc())
            finally:
                # Cleanup
                if os.path.exists(temp_in_path):
                    try:
                        os.remove(temp_in_path)
                    except:
                        pass
                if os.path.exists(temp_out_path):
                    try:
                        os.remove(temp_out_path)
                    except:
                        pass
