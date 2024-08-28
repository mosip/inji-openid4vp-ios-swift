import XCTest
@testable import OpenId4VP

class OpenId4VPTests: XCTestCase {
    var openId4Vp: OpenId4VP!
    var mockNetworkManager: MockNetworkManager!
    
    let authorizationRequest = AuthorizationRequest(
        clientId: "client_id",
        presentationDefinition: "presentationDefinition",
        scope: "scope",
        responseType: "responseType",
        responseMode: "responseMode",
        nonce: "nonce",
        state: "state",
        responseUri: "https://example.com"
    )
    
    let jws = "wemcn3234ns"
    let signatureAlgoType = "RsaSignature2018"
    let publicKey = "MIICCgKCAgEA0IEd3E5CvLAbGvr/ysYT2TLE7WDrPBHGk8pwGqVvlrrFtZJ9wT8E"
    let domain = "https://example"
    let descriptorMap: [DescriptorMap] = [
        DescriptorMap(id: "bank_input", format: .ldp_vc, path: "$.verifiableCredential[0]"),
        DescriptorMap(id: "bank_input", format: .ldp_vc, path: "$.verifiableCredential[1]")
    ]
    
    let vpToken = VpTokenForSigning(verifiableCredential: ["VC1", "VC2"],holder: "")
    
    override func setUp() {
        super.setUp()
        mockNetworkManager = MockNetworkManager()
        
        openId4Vp = OpenId4VP(traceabilityId: "AXESWSAW123", networkManager: mockNetworkManager)
        openId4Vp.setPresentationDefinitionId("AWSE")
        openId4Vp.setResponseUri("https://example.com")
        openId4Vp.authorizationRequest = authorizationRequest
        
        AuthorizationResponse.descriptorMap = descriptorMap
        AuthorizationResponse.vpTokenForSigning = vpToken
    }
    
    override func tearDown() {
        openId4Vp = nil
        mockNetworkManager = nil
        super.tearDown()
    }
    
    let testVerifierList:  [[String: Any]]  = [
        [
            "client_id": "https://injiverify.dev2.mosip.net",
            "redirect_uri": [
                "https://injiverify.qa-inji.mosip.net/redirect",
                "https://injiverify.dev2.mosip.net/redirect"
            ]
        ],
        [
            "client_id": "https://injiverify.dev1.mosip.net",
            "redirect_uri": [
                "https://injiverify.qa-inji.mosip.net/redirect",
                "https://injiverify.dev1.mosip.net/redirect"
            ]
        ]
    ]
    
    let testValidEncodedVpRequest = "T1BFTklENFZQOi8vYXV0aG9yaXplP2NsaWVudF9pZD1odHRwczovL2luaml2ZXJpZnkuZGV2Mi5tb3NpcC5uZXQmcHJlc2VudGF0aW9uX2RlZmluaXRpb249eyJpZCI6IiMyMzQ1MzMzIiwiaW5wdXRfZGVzY3JpcHRvcnMiOlt7ImlkIjoiYmFua2luZ19pbnB1dF8xIiwibmFtZSI6IkJhbmsgQWNjb3VudCBJbmZvcm1hdGlvbiIsInB1cnBvc2UiOiJXZSBjYW4gb25seSByZW1pdCBwYXltZW50IHRvIGEgY3VycmVudGx5LXZhbGlkIGJhbmsgYWNjb3VudCBpbiB0aGUgVVMsIEZyYW5jZSwgb3IgR2VybWFueSwgc3VibWl0dGVkIGFzIGFuIEFCQSBBY2N0IG9yIElCQU4uIiwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiQuY3JlZGUiXSwicHVycG9zZSI6IldlIGNhbiB1c2UgZm9yICAjIHZlcmlmaWNhdGlvbiBwdXJwb3NlICMgZm9yIGFueXRoaW5nIiwiZmlsdGVyIjp7InR5cGUiOiJzdHJpbmciLCJwYXR0ZXJuIjoiXlswLTldezl9fF4oW2EtekEtWl0pezR9KFthLXpBLVpdKXsyfShbMC05YS16QS1aXSl7Mn0oWzAtOWEtekEtWl17M30pPyQifX0seyJwYXRoIjpbIiQudmMuY3JlZGVudGlhbCIsIiQudmMuY3JlZGVudGlhbFN1YmplY3QuYWNjb3VudFsqXS5yb3V0ZSIsIiQuYWNjb3VudFsqXS5yb3V0ZSJdLCJwdXJwb3NlIjoiV2UgY2FuIHVzZSBmb3IgdmVyaWZpY2F0aW9uIHB1cnBvc2UiLCJmaWx0ZXIiOnsidHlwZSI6InN0cmluZyIsInBhdHRlcm4iOiJeWzAtOV17OX18XihbYS16QS1aXSl7NH0oW2EtekEtWl0pezJ9KFswLTlhLXpBLVpdKXsyfShbMC05YS16QS1aXXszfSk/JCJ9fV19fV19JnJlc3BvbnNlX3R5cGU9dnBfdG9rZW4mcmVzcG9uc2VfbW9kZT1kaXJlY3RfcG9zdCZub25jZT1WYlJSQi9MVHhMaVhtVk5adXlNTzhBPT0mc3RhdGU9K21SUWUxZDZwQm9KcUY2QWIyOGtsZz09JnJlc3BvbnNlX3VyaT0vdmVyaWZpZXIvdnAtcmVzcG9uc2UgSFRUUC8xLjE="
    
    let testInvalidPresentationDefinitionVpRequest = "T1BFTklENFZQOi8vYXV0aG9yaXplP2NsaWVudF9pZD1odHRwczovL2luaml2ZXJpZnkuZGV2Mi5tb3NpcC5uZXQmcHJlc2VudGF0aW9uX2RlZmluaXRpb249eyJpbnB1dF9kZXNjcmlwdG9ycyI6W119JnJlc3BvbnNlX3R5cGU9dnBfdG9rZW4mcmVzcG9uc2VfbW9kZT1kaXJlY3RfcG9zdCZub25jZT1WYlJSQi9MVHhMaVhtVk5adXlNTzhBPT0mc3RhdGU9K21SUWUxZDZwQm9KcUY2QWIyOGtsZz09JnJlc3BvbnNlX3VyaT0vdmVyaWZpZXIvdnAtcmVzcG9uc2UgSFRUUC8xLjE="
    
    let invalidVpRequest = "T1BFTklENFZQOi8vYXV0aG9yaXplP2NsaWVudF9pZD1odHRwcyUzQSUyRiUyRmluaml2ZXJpZnkuZGV2Mi5tb3NpcC5uZXQmcmVzcG9uc2VfdHlwZT12cF90b2tlbiZyZXNwb25zZV9tb2RlPWRpcmVjdF9wb3N0Jm5vbmNlPVZiUlJCL0xUeExpWG1WTlp1eU1POEE9PSZzdGF0ZT0rbVJRZTFkNnBCb0pxRjZBYjI4a2xnPT0mcmVzcG9uc2VfdXJpPS92ZXJpZmllci92cC1yZXNwb25zZSBIVFRQLzEuMQ=="
    
    func testReturnDataForValidRequest() async {
        
        let verifiers = createVerifiers(from: testVerifierList)
        
        let decoded: Any?
        
        do {
            decoded = try await openId4Vp.authenticateVerifier(encodedAuthorizationRequest: testValidEncodedVpRequest, trustedVerifierJSON: verifiers)
        } catch {
            decoded = nil
        }
        XCTAssertTrue(decoded is AuthenticationResponse, "decodedResponse should be an instance of AuthenticationResponse")
        XCTAssertTrue(decoded != nil, "decodedResponse should not be null")
    }
    
    func testMissingPresentationDefinitionFields() async {
        let verifiers = createVerifiers(from: testVerifierList)
        
        let error = await Task {
            try await openId4Vp.authenticateVerifier(encodedAuthorizationRequest: testInvalidPresentationDefinitionVpRequest, trustedVerifierJSON: verifiers)
        }.result
        
        switch error {
        case .failure(let thrownError):
            XCTAssertEqual(thrownError as? AuthorizationRequestException, AuthorizationRequestException.invalidPresentationDefinition)
        case .success: break
        }
    }
    
    func testMissingRequiredFieldsInRequest() async {
        
        let verifiers = createVerifiers(from: testVerifierList)
        
        let error = await Task {
            try await openId4Vp.authenticateVerifier(encodedAuthorizationRequest: invalidVpRequest, trustedVerifierJSON: verifiers)
        }.result
        
        switch error {
        case .failure(let thrownError):
            XCTAssertEqual(thrownError as? AuthorizationRequestException, AuthorizationRequestException.invalidQueryParams(message: "Either presentation_definition or scope request param must be present."))
        case .success: break
        }
    }
    
    func testUUIDGeneration() {
        
        let vpToken = UUIDGenerator.generateUUID()
        let presentationSubmissionId = UUIDGenerator.generateUUID()
        let presentationSubmission = PresentationSubmission(definition_id: "", descriptor_map: AuthorizationResponse.descriptorMap!)
        
        XCTAssertNotNil(vpToken,presentationSubmissionId)
        XCTAssertNotNil(presentationSubmission.id)
    }
    
    func testShareVerifiablePresentation() async{
        let credentialsMap: [String: [String]] = ["bank_input":["VC1","VC2"]]
        let received: String?
        
        do {
            received = try await openId4Vp.constructVerifiablePresentationToken(credentialsMap: credentialsMap)
        }catch{
            received = nil
        }
        XCTAssertNotNil(received,  "The response should not be nil for valid credentials map")
    }
    
    func testSendVpSuccess() async throws {
        
        let vcResponseMetaData = VPResponseMetadata(jws: jws, signatureAlgorithm: signatureAlgoType, publicKey: publicKey, domain: domain)
        
        let response = try await openId4Vp.shareVerifiablePresentation(vpResponseMetadata: vcResponseMetaData)
        
        XCTAssertEqual(response, "Success: Request completed successfully.")
    }
    
    func testSendVpFailure() async {
        
        let errorMessage = "Network Request failed with error response: response"
        mockNetworkManager.error = NetworkRequestException.networkRequestFailed(message: errorMessage)
        
        let vcResponseMetaData = VPResponseMetadata(jws: jws, signatureAlgorithm: signatureAlgoType, publicKey: publicKey, domain: domain)
        
        
        do {
            let _ = try await openId4Vp.shareVerifiablePresentation(vpResponseMetadata: vcResponseMetaData)
        } catch let error as NetworkRequestException {
            switch error {
            case .networkRequestFailed(let message):
                XCTAssertEqual(message, errorMessage, "Unexpected error message: \(message)")
            default:
                XCTFail("Expected NetworkRequestException.networkRequestFailed but got \(error)")
            }
        } catch {
        }
    }
}
