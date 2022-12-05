import {GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import type {AwsRegion} from '../../pricing/aws-regions';
import {getStsClient} from '../../shared/aws-clients';
import type {EvalDecision, SimulationResult} from './simulate-rule';
import {simulateRule} from './simulate-rule';
import {requiredPermissions} from './user-permissions';

const getEmojiForStatus = (decision: EvalDecision) => {
	switch (decision) {
		case 'allowed':
			return '✅';
		default:
			return '❌';
	}
};

export const logPermissionOutput = (output: SimulationResult) => {
	return [getEmojiForStatus(output.decision), output.name].join(' ');
};

export type SimulatePermissionsInput = {
	region: AwsRegion;
	onSimulation?: (result: SimulationResult) => void;
};

export type SimulatePermissionsOutput = {
	results: SimulationResult[];
};

/**
 * @description Simulates calls using the AWS Simulator to validate the correct permissions.
 * @link http://remotion.dev/docs/lambda/simulatepermissions
 * @param {AwsRegion} options.region The region which you would like to validate
 * @param {(result: SimulationResult) => void} options.onSimulation The region which you would like to validate
 * @returns {Promise<SimulatePermissionsOutput>} See documentation for detailed response structure.
 */
export const simulatePermissions = async (
	options: SimulatePermissionsInput
): Promise<SimulatePermissionsOutput> => {
	const callerIdentity = await getStsClient(options.region).send(new GetCallerIdentityCommand({}));

	if (!callerIdentity || !callerIdentity.Arn) {
		throw new Error('No valid AWS calling identity detected');
	}

	const arnComponents = callerIdentity.Arn!.match(/arn:aws:([\w\d]+)::(\d+):([^\/]+)(.*)/)
	if (!arnComponents) {
		throw new Error('Unsupported AWS ARN detected');
	}

	let arn = undefined;
	if (arnComponents[1] === 'iam' && arnComponents[3] === 'user') {
		arn = callerIdentity.Arn as string;
	} else if (arnComponents[1] === 'sts' && arnComponents[3] === 'assumed-role') {
		const assumedRoleComponents = arnComponents[4].match(/\/([^\/]+)\/(.*)/)
		if (!assumedRoleComponents) {
			throw new Error('Unsupported AWS Assumed-Role ARN detected');
		}
		arn = `arn:aws:iam::${arnComponents[2]}:role/${assumedRoleComponents[1]}`
	} else {
		throw new Error('Unsupported AWS ARN detected');
	}

	const results: SimulationResult[] = [];

	for (const per of requiredPermissions) {
		const result = await simulateRule({
			actionNames: per.actions,
			arn: arn as string,
			region: options.region,
			resource: per.resource,
			retries: 2,
		});
		for (const res of result) {
			results.push(res);
			options.onSimulation?.(res);
		}
	}

	return {results};
};
