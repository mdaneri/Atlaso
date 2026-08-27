@{
    Severity = @('Error', 'Warning')

    # These legacy style and ShouldProcess rules are covered by Atlaso's
    # incremental comment-help gate or require separate behavior-changing work.
    # Runtime, parser, credential, empty-catch, runspace, and dynamic-execution
    # rules remain enabled for every tracked PowerShell source.
    ExcludeRules = @(
        'PSAvoidGlobalVars'
        'PSAvoidUsingPositionalParameters'
        'PSAvoidUsingWriteHost'
        'PSProvideCommentHelp'
        'PSReviewUnusedParameter'
        'PSShouldProcess'
        'PSUseApprovedVerbs'
        'PSUseDeclaredVarsMoreThanAssignments'
        'PSUseShouldProcessForStateChangingFunctions'
        'PSUseSingularNouns'
        'PSUseSupportsShouldProcess'
    )
}
