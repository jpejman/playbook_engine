# Python Script Classification Report

## Analysis Summary

**Total Python Files Analyzed:** 151  
**Production Root Scripts Identified:** 1
- `scripts/prod/phase1_continuous_execution_system_v0_2_0_fixed_terminal_dedup.py`

**Note:** The second production script mentioned (`scripts/prod/phase1_continuous_execution_system_v0_2_0.py`) was not found in the repository.

## File Categories

| Category | Count | Description |
|----------|-------|-------------|
| **prod** | 39 | Production scripts and source code |
| **dev_diagnostics** | 57 | Development and diagnostic scripts |
| **tools** | 54 | Utility scripts, tests, and operational tools |
| **archive** | 1 | Archived/copy files |

## Detailed Classification Table

| Filename | Path | Imported By | Calls Into | Called By Prod | Category |
|----------|------|-------------|------------|----------------|----------|
| **Production Root Scripts** |
| phase1_continuous_execution_system_v0_2_0_fixed_terminal_dedup.py | scripts/prod/phase1_continuous_execution_system_v0_2_0_fixed_terminal_dedup.py | 0 | 1 | yes | prod |
| **Other Production Scripts** |
| 02_85_build_context_snapshot_v0_1_0.py | scripts/prod/02_85_build_context_snapshot_v0_1_0.py | 0 | 0 | no | prod |
| 03_01_run_playbook_generation_v0_1_1_real_retrieval.py | scripts/prod/03_01_run_playbook_generation_v0_1_1_real_retrieval.py | 0 | 0 | no | prod |
| 06_08_qa_enforcement_gate_canonical_v0_2_0.py | scripts/prod/06_08_qa_enforcement_gate_canonical_v0_2_0.py | 0 | 0 | no | prod |
| phase1_direct_cve_runner.py | scripts/prod/phase1_direct_cve_runner.py | 1 | 0 | yes | prod |
| phase1_single_cve_continuous_runner.py | scripts/prod/phase1_single_cve_continuous_runner.py | 0 | 0 | no | prod |
| production_selector_opensearch_first.py | scripts/prod/production_selector_opensearch_first.py | 0 | 0 | no | prod |
| run_production_chain_opensearch_first.py | scripts/prod/run_production_chain_opensearch_first.py | 0 | 0 | no | prod |
| time_utils.py | scripts/prod/time_utils.py | 1 | 0 | yes | prod |
| update_schema_for_diagnostics.py | scripts/prod/update_schema_for_diagnostics.py | 0 | 0 | no | prod |
| **Source Code (prod)** |
| playbook_agent.py | src/agents/playbook_agent.py | 0 | 0 | no | prod |
| All src/ directories (38 files) | Various src/ paths | 0-1 | 0-2 | no | prod |
| **Development Diagnostics** |
| 57 files in scripts/dev_diagnostics/ | scripts/dev_diagnostics/*.py | 0 | 0-1 | no | dev_diagnostics |
| **Tools & Operations** |
| 00_01_verify_db_v0_1_1.py | scripts/ops/00_01_verify_db_v0_1_1.py | 0 | 0 | no | tools |
| 00_02_init_db_v0_1_1.py | scripts/ops/00_02_init_db_v0_1_1.py | 0 | 0 | no | tools |
| 9 other ops scripts | scripts/ops/*.py | 0 | 0 | no | tools |
| Various test files | tests/*.py | 0 | 0-1 | no | tools |
| Various utility scripts | *.py (root) | 0-4 | 0-1 | no | tools |
| **Archive** |
| final_verification copy.py | final_verification copy.py | 0 | 1 | no | archive |

## Dependency Analysis

### Production Root Dependencies
The main production script `phase1_continuous_execution_system_v0_2_0_fixed_terminal_dedup.py` imports:
1. `src.retrieval.opensearch_client.RealOpenSearchClient`
2. `src.utils.db.DatabaseClient`
3. `scripts.prod.time_utils` (get_utc_now, datetime_to_iso, calculate_duration_seconds)
4. `phase1_selector_corrected.Phase1CVESelectorCorrected` (dynamic import)
5. `scripts.prod.phase1_direct_cve_runner.Phase1DirectCVERunner` (dynamic import)

### Key Findings

1. **Production Ecosystem**: 39 files categorized as production code
2. **Development Focus**: 57 diagnostic scripts indicate active development
3. **Modular Architecture**: Source code organized in `src/` with clear separation
4. **Operational Tools**: 10 operational scripts in `scripts/ops/`
5. **Test Coverage**: Multiple test files in `tests/` directory

### Import/Export Patterns

- Most files show 0 imports from other project files, suggesting:
  - Standalone scripts
  - Use of external libraries only
  - Potential for dependency analysis refinement

- Files with imports:
  - `phase1_selector_corrected.py`: Imported by 4 files
  - `canonical_prompt_template_v1_2_0.py`: Imported by 1 file
  - `time_utils.py`: Imported by production root

## Recommendations

1. **Consolidate Development Scripts**: 57 dev_diagnostics scripts could be organized or documented
2. **Document Dependencies**: Create dependency documentation for production system
3. **Archive Old Files**: Consider archiving `final_verification copy.py` and similar duplicates
4. **Test Coverage**: Expand test coverage for production modules
5. **Dependency Management**: Implement proper import tracking for better maintainability

## Notes

- Analysis based on file paths and simple import detection
- Actual runtime dependencies may differ from static analysis
- Some files categorized as "tools" may be production-critical
- Further analysis needed for dynamic imports and runtime dependencies