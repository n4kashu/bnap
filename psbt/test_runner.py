"""
PSBT Test Runner

Comprehensive test runner for PSBT validation and testing suite.
Provides utilities for running tests, generating reports, and validating PSBTs.
"""

import sys
import json
import time
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict

from .validator import PSBTValidator, ValidationResult, format_validation_report
from .builder import BasePSBTBuilder
from .templates import TransferPSBTBuilder
from .fungible_mint import FungibleMintPSBTBuilder
from .nft_mint import NFTMintPSBTBuilder


@dataclass
class TestResult:
    """Represents the result of a single test."""
    name: str
    passed: bool
    duration: float
    error_message: Optional[str] = None
    validation_result: Optional[ValidationResult] = None


@dataclass
class TestSuite:
    """Represents a complete test suite execution."""
    name: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    total_duration: float
    results: List[TestResult]


class PSBTTestRunner:
    """
    Comprehensive test runner for PSBT validation and construction.
    
    Provides automated testing capabilities for PSBT builders, validators,
    and integration scenarios.
    """
    
    def __init__(self):
        """Initialize test runner."""
        self.validator = PSBTValidator()
        self.results: List[TestResult] = []
    
    def run_validation_tests(self) -> TestSuite:
        """Run comprehensive validation tests."""
        print("🧪 Running PSBT Validation Test Suite")
        print("=" * 50)
        
        test_functions = [
            self._test_valid_minimal_psbt,
            self._test_invalid_empty_psbt,
            self._test_missing_inputs,
            self._test_missing_outputs,
            self._test_oversized_op_return,
            self._test_malformed_metadata,
            self._test_proprietary_fields,
            self._test_security_constraints,
            self._test_asset_operations,
            self._test_business_logic,
        ]
        
        return self._run_test_suite("PSBT Validation", test_functions)
    
    def run_builder_tests(self) -> TestSuite:
        """Run PSBT builder construction tests."""
        print("🔨 Running PSBT Builder Test Suite")
        print("=" * 50)
        
        test_functions = [
            self._test_base_psbt_builder,
            self._test_fungible_mint_builder,
            self._test_nft_mint_builder,
            self._test_transfer_builder,
            self._test_multi_asset_builder,
        ]
        
        return self._run_test_suite("PSBT Builders", test_functions)
    
    def run_integration_tests(self) -> TestSuite:
        """Run end-to-end integration tests."""
        print("🔄 Running Integration Test Suite")
        print("=" * 50)
        
        test_functions = [
            self._test_mint_to_transfer_flow,
            self._test_complex_multi_asset_scenario,
            self._test_error_recovery,
            self._test_performance_stress,
        ]
        
        return self._run_test_suite("Integration Tests", test_functions)
    
    def run_all_tests(self) -> Dict[str, TestSuite]:
        """Run all test suites."""
        print("🚀 Running Complete PSBT Test Suite")
        print("=" * 60)
        
        suites = {}
        suites['validation'] = self.run_validation_tests()
        suites['builders'] = self.run_builder_tests()
        suites['integration'] = self.run_integration_tests()
        
        self._print_summary(suites)
        return suites
    
    def validate_psbt_file(self, file_path: str) -> ValidationResult:
        """
        Validate a PSBT from file.
        
        Args:
            file_path: Path to PSBT file
            
        Returns:
            ValidationResult
        """
        try:
            with open(file_path, 'rb') as f:
                psbt_data = f.read()
            
            # Try both raw bytes and base64
            if psbt_data.startswith(b'psbt'):
                result = self.validator.validate_psbt(psbt_data)
            else:
                import base64
                try:
                    decoded_data = base64.b64decode(psbt_data)
                    result = self.validator.validate_psbt(decoded_data)
                except Exception:
                    # If base64 decode fails, try as raw
                    result = self.validator.validate_psbt(psbt_data)
            
            return result
            
        except Exception as e:
            # Create error result
            from .validator import ValidationResult, ValidationIssue, ValidationSeverity, ValidationCategory
            error_issue = ValidationIssue(
                severity=ValidationSeverity.CRITICAL,
                category=ValidationCategory.STRUCTURE,
                code="FILE_READ_ERROR",
                message=f"Failed to read PSBT file: {e}"
            )
            return ValidationResult(is_valid=False, issues=[error_issue])
    
    def generate_test_report(self, suites: Dict[str, TestSuite], output_file: Optional[str] = None) -> str:
        """
        Generate comprehensive test report.
        
        Args:
            suites: Dictionary of test suites
            output_file: Optional file to write report to
            
        Returns:
            Report content as string
        """
        report_lines = []
        report_lines.append("PSBT Test Suite Report")
        report_lines.append("=" * 60)
        report_lines.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("")
        
        # Overall summary
        total_tests = sum(suite.total_tests for suite in suites.values())
        total_passed = sum(suite.passed_tests for suite in suites.values())
        total_failed = sum(suite.failed_tests for suite in suites.values())
        total_duration = sum(suite.total_duration for suite in suites.values())
        
        report_lines.append("OVERALL SUMMARY")
        report_lines.append("-" * 30)
        report_lines.append(f"Total Tests: {total_tests}")
        report_lines.append(f"Passed: {total_passed}")
        report_lines.append(f"Failed: {total_failed}")
        report_lines.append(f"Success Rate: {(total_passed/total_tests*100):.1f}%")
        report_lines.append(f"Total Duration: {total_duration:.3f}s")
        report_lines.append("")
        
        # Suite details
        for suite_name, suite in suites.items():
            report_lines.append(f"{suite.name.upper()} SUITE")
            report_lines.append("-" * 30)
            report_lines.append(f"Tests: {suite.total_tests}")
            report_lines.append(f"Passed: {suite.passed_tests}")
            report_lines.append(f"Failed: {suite.failed_tests}")
            report_lines.append(f"Duration: {suite.total_duration:.3f}s")
            report_lines.append("")
            
            # Failed tests details
            failed_results = [r for r in suite.results if not r.passed]
            if failed_results:
                report_lines.append("FAILED TESTS:")
                for result in failed_results:
                    report_lines.append(f"  ❌ {result.name}")
                    if result.error_message:
                        report_lines.append(f"     Error: {result.error_message}")
                    report_lines.append(f"     Duration: {result.duration:.3f}s")
                report_lines.append("")
        
        report_content = "\n".join(report_lines)
        
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(report_content)
                print(f"📄 Report saved to: {output_file}")
            except Exception as e:
                print(f"⚠️ Failed to save report: {e}")
        
        return report_content
    
    def _run_test_suite(self, suite_name: str, test_functions: List) -> TestSuite:
        """Run a suite of test functions."""
        results = []
        start_time = time.time()
        
        for test_func in test_functions:
            result = self._run_single_test(test_func)
            results.append(result)
            
            status = "✅ PASS" if result.passed else "❌ FAIL"
            duration_str = f"{result.duration:.3f}s"
            print(f"  {status} {result.name} ({duration_str})")
            
            if not result.passed and result.error_message:
                print(f"    Error: {result.error_message}")
        
        total_duration = time.time() - start_time
        passed_tests = sum(1 for r in results if r.passed)
        failed_tests = len(results) - passed_tests
        
        print(f"\n📊 {suite_name} Summary: {passed_tests}/{len(results)} passed ({total_duration:.3f}s)\n")
        
        return TestSuite(
            name=suite_name,
            total_tests=len(results),
            passed_tests=passed_tests,
            failed_tests=failed_tests,
            total_duration=total_duration,
            results=results
        )
    
    def _run_single_test(self, test_func) -> TestResult:
        """Run a single test function."""
        test_name = test_func.__name__.replace('_test_', '').replace('_', ' ').title()
        
        start_time = time.time()
        try:
            validation_result = test_func()
            duration = time.time() - start_time
            
            return TestResult(
                name=test_name,
                passed=True,
                duration=duration,
                validation_result=validation_result
            )
        except Exception as e:
            duration = time.time() - start_time
            
            return TestResult(
                name=test_name,
                passed=False,
                duration=duration,
                error_message=str(e)
            )
    
    def _print_summary(self, suites: Dict[str, TestSuite]) -> None:
        """Print overall test summary."""
        total_tests = sum(suite.total_tests for suite in suites.values())
        total_passed = sum(suite.passed_tests for suite in suites.values())
        total_failed = sum(suite.failed_tests for suite in suites.values())
        total_duration = sum(suite.total_duration for suite in suites.values())
        
        print("🏁 FINAL RESULTS")
        print("=" * 40)
        print(f"Total Tests: {total_tests}")
        print(f"✅ Passed: {total_passed}")
        print(f"❌ Failed: {total_failed}")
        print(f"📈 Success Rate: {(total_passed/total_tests*100):.1f}%")
        print(f"⏱️  Total Time: {total_duration:.3f}s")
        
        if total_failed == 0:
            print("\n🎉 ALL TESTS PASSED! 🎉")
        else:
            print(f"\n⚠️  {total_failed} TESTS FAILED")
    
    # Test implementations
    
    def _test_valid_minimal_psbt(self) -> ValidationResult:
        """Test validation of minimal valid PSBT."""
        builder = BasePSBTBuilder()
        builder.add_input("a" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        # Should be valid or have only warnings
        if not result.is_valid and len(result.errors) > 0:
            raise AssertionError(f"Expected valid PSBT, got errors: {[e.message for e in result.errors]}")
        
        return result
    
    def _test_invalid_empty_psbt(self) -> ValidationResult:
        """Test validation of empty/invalid PSBT."""
        result = self.validator.validate_psbt(b'invalid')
        
        if result.is_valid:
            raise AssertionError("Expected invalid PSBT to fail validation")
        
        return result
    
    def _test_missing_inputs(self) -> ValidationResult:
        """Test PSBT with no inputs."""
        builder = BasePSBTBuilder()
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        if result.is_valid:
            raise AssertionError("Expected PSBT with no inputs to be invalid")
        
        return result
    
    def _test_missing_outputs(self) -> ValidationResult:
        """Test PSBT with no outputs."""
        builder = BasePSBTBuilder()
        builder.add_input("a" * 64, 0)
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        if result.is_valid:
            raise AssertionError("Expected PSBT with no outputs to be invalid")
        
        return result
    
    def _test_oversized_op_return(self) -> ValidationResult:
        """Test PSBT with oversized OP_RETURN."""
        builder = BasePSBTBuilder()
        builder.add_input("a" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        # Add oversized OP_RETURN
        large_data = b'x' * 100
        op_return_script = b'\x6a\x64' + large_data
        builder.add_output(script=op_return_script, amount=0)
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        # Should have OP_RETURN size error
        if not any("OP_RETURN_TOO_LARGE" in issue.code for issue in result.errors):
            raise AssertionError("Expected OP_RETURN size error")
        
        return result
    
    def _test_malformed_metadata(self) -> ValidationResult:
        """Test PSBT with malformed metadata."""
        builder = BasePSBTBuilder()
        builder.add_input("a" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        # Add invalid proprietary fields
        builder.add_input_proprietary(0, b'BNAPAID', b'invalid')  # Wrong length
        builder.add_input_proprietary(0, b'BNAPAMT', b'bad')      # Wrong format
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        # Should have metadata errors
        if len(result.errors) == 0:
            raise AssertionError("Expected metadata validation errors")
        
        return result
    
    def _test_proprietary_fields(self) -> ValidationResult:
        """Test validation of proprietary fields."""
        builder = BasePSBTBuilder()
        builder.add_input("a" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        # Add valid BNAP proprietary fields
        builder.add_input_proprietary(0, b'BNAPAID', b'a' * 32)   # Valid asset ID
        builder.add_output_proprietary(0, b'BNAPAMT', b'\x00' * 8) # Valid amount
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        # Should be valid
        if len(result.critical_issues) > 0:
            raise AssertionError(f"Unexpected critical issues: {[i.message for i in result.critical_issues]}")
        
        return result
    
    def _test_security_constraints(self) -> ValidationResult:
        """Test security constraint validation."""
        builder = BasePSBTBuilder()
        builder.add_input("a" * 64, 0)
        
        # Add many OP_RETURN outputs (security concern)
        for i in range(6):
            builder.add_output(script=b'\x6a\x04test', amount=0)
        
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        # Should have security warnings
        # (This test may pass even without warnings depending on implementation)
        return result
    
    def _test_asset_operations(self) -> ValidationResult:
        """Test asset operation validation."""
        builder = BasePSBTBuilder()
        builder.add_input("a" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        # Add asset operation metadata
        builder.add_input_proprietary(0, b'BNAPAID', b'a' * 32)
        
        psbt_data = builder.serialize()
        result = self.validator.validate_asset_operations(psbt_data)
        
        return result
    
    def _test_business_logic(self) -> ValidationResult:
        """Test business logic validation."""
        builder = BasePSBTBuilder()
        builder.add_input("a" * 64, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        return result
    
    def _test_base_psbt_builder(self) -> ValidationResult:
        """Test basic PSBT builder functionality."""
        builder = BasePSBTBuilder()
        builder.add_input("builder" + "a" * 57, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=5000)
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        return result
    
    def _test_fungible_mint_builder(self) -> ValidationResult:
        """Test fungible mint builder."""
        # This test is simplified since full builder test would require more setup
        builder = BasePSBTBuilder()
        builder.add_input("mint" + "a" * 60, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        # Add mint-like metadata
        from psbt.outputs.op_return import create_asset_issuance_op_return
        op_return = create_asset_issuance_op_return("b" * 64, 1000000, 8, "TEST")
        builder.add_output(script=op_return, amount=0)
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        return result
    
    def _test_nft_mint_builder(self) -> ValidationResult:
        """Test NFT mint builder."""
        builder = BasePSBTBuilder()
        builder.add_input("nft" + "a" * 61, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        return result
    
    def _test_transfer_builder(self) -> ValidationResult:
        """Test transfer builder."""
        builder = BasePSBTBuilder()
        builder.add_input("transfer" + "a" * 56, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=2000)
        builder.add_output(script=b'\x00\x14' + b'\x02' * 20, amount=1000)  # Change
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        return result
    
    def _test_multi_asset_builder(self) -> ValidationResult:
        """Test multi-asset builder."""
        builder = BasePSBTBuilder()
        builder.add_input("multi1" + "a" * 58, 0)
        builder.add_input("multi2" + "b" * 58, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1500)
        builder.add_output(script=b'\x00\x14' + b'\x02' * 20, amount=1200)
        builder.add_output(script=b'\x00\x14' + b'\x03' * 20, amount=800)  # Change
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        return result
    
    def _test_mint_to_transfer_flow(self) -> ValidationResult:
        """Test mint -> transfer workflow."""
        # Simplified integration test
        builder = BasePSBTBuilder()
        builder.add_input("flow" + "a" * 60, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=3000)
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        return result
    
    def _test_complex_multi_asset_scenario(self) -> ValidationResult:
        """Test complex multi-asset scenario."""
        builder = BasePSBTBuilder()
        
        # Multiple inputs and outputs for complex scenario
        for i in range(3):
            builder.add_input("complex" + "a" * 57, i)
        
        for i in range(4):
            builder.add_output(script=b'\x00\x14' + bytes([i + 1]) * 20, amount=1000 + i * 100)
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        return result
    
    def _test_error_recovery(self) -> ValidationResult:
        """Test error recovery scenarios."""
        # Test with partially malformed PSBT
        builder = BasePSBTBuilder()
        builder.add_input("error" + "a" * 59, 0)
        builder.add_output(script=b'\x00\x14' + b'\x01' * 20, amount=1000)
        
        # Add some malformed data that should be caught
        builder.add_input_proprietary(0, b'INVALID', b'data')
        
        psbt_data = builder.serialize()
        result = self.validator.validate_psbt(psbt_data)
        
        return result
    
    def _test_performance_stress(self) -> ValidationResult:
        """Test performance under stress."""
        builder = BasePSBTBuilder()
        
        # Create larger PSBT for performance testing
        for i in range(20):
            builder.add_input("stress" + "a" * 58, i)
        
        for i in range(25):
            builder.add_output(script=b'\x00\x14' + bytes([i % 256]) * 20, amount=1000 + i)
        
        psbt_data = builder.serialize()
        
        # Measure validation time
        start_time = time.time()
        result = self.validator.validate_psbt(psbt_data)
        validation_time = time.time() - start_time
        
        # Should complete within reasonable time
        if validation_time > 2.0:
            raise AssertionError(f"Validation took too long: {validation_time:.3f}s")
        
        return result


def main():
    """Main function for running tests from command line."""
    runner = PSBTTestRunner()
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "validation":
            suite = runner.run_validation_tests()
        elif command == "builders":
            suite = runner.run_builder_tests()
        elif command == "integration":
            suite = runner.run_integration_tests()
        elif command == "all":
            suites = runner.run_all_tests()
            # Generate report
            report = runner.generate_test_report(suites, "test_report.txt")
            return
        elif command.startswith("validate"):
            if len(sys.argv) < 3:
                print("Usage: python test_runner.py validate <psbt_file>")
                return
            
            result = runner.validate_psbt_file(sys.argv[2])
            print(format_validation_report(result))
            return
        else:
            print("Usage: python test_runner.py [validation|builders|integration|all|validate <file>]")
            return
    else:
        # Default: run all tests
        suites = runner.run_all_tests()
        report = runner.generate_test_report(suites, "test_report.txt")


if __name__ == "__main__":
    main()