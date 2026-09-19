from scanner.aws.collectors.lambda_collector import LambdaDataCollector


def collect_lambda_functions(
    collector: LambdaDataCollector,
) -> list[dict]:
    return collector.collect_functions()


LAMBDA_DATA_SOURCE_HANDLERS = {
    "lambda_functions": collect_lambda_functions,
}
