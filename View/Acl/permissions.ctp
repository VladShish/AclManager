<?php $groups = (array)Configure::read('AclManager.groups');?>

<div class="form">
	<h3><?= sprintf(__("%s permissions"), $aroAlias);?></h3>

	<?= $this->Form->create('Perms'); ?>

	<table>
		<tr>
			<th>Action</th>
			<?php foreach ($aros as $index => $aro): ?>
				<?php
				if (!empty($groups) && !in_array($aro['Group']['id'], $groups)) :
					continue;
				endif;

				$aro = array_shift($aro);
				?>
				<th><?= h($aro[$aroDisplayField]); ?></th>
			<?php endforeach; ?>
		</tr>
		<?php
		$uglyIdent = Configure::read('AclManager.uglyIdent'); 
		$lastIdent = null;
		foreach ($acos as $id => $aco) :
			if (in_array($aco['Aco']['alias'], Configure::read('AclManager.ignoreActions'))) :
				continue;
			endif;

			$action = $aco['Action'];
			$alias = $aco['Aco']['alias'];
			$ident = substr_count($action, '/');
			if ($ident <= $lastIdent && !is_null($lastIdent)) :
				for ($i = 0; $i <= ($lastIdent - $ident); $i++) : ?>
					</tr>
		<?php	endfor;
			endif;
		?>
			<?php if ($ident != $lastIdent) : ?>
				<tr class='aclmanager-ident-<?= $ident; ?>'>
			<?php endif; ?>

			<td><?= ($ident == 1 ? "<strong>" : "" ) . ($uglyIdent ? str_repeat("&nbsp;&nbsp;", $ident) : "") . h($alias) . ($ident == 1 ? "</strong>" : "" ); ?></td>

			<?php foreach ($aros as $index => $aro):
				if (!empty($groups) && !in_array($aro['Group']['id'], $groups)) :
					continue;
				endif;

				$inherit = $this->Form->value("Perms." . str_replace("/", ":", $action) . ".{$aroAlias}:{$aro[$aroAlias]['id']}-inherit");
				$allowed = $this->Form->value("Perms." . str_replace("/", ":", $action) . ".{$aroAlias}:{$aro[$aroAlias]['id']}");
				$icon = $this->Html->image(($allowed ? 'test-pass-icon.png' : 'test-fail-icon.png'));

				if ($inherit) :
					$value = 'inherit';
				else :
					$value = $allowed ? 'allow' : 'deny';
				endif;
			?>
				<td><?= $icon . " " . $this->Form->select(
					"Perms." . str_replace("/", ":", $action) . ".{$aroAlias}:{$aro[$aroAlias]['id']}",
					array(array('inherit' => __('Inherit'), 'allow' => __('Allow'), 'deny' => __('Deny'))),
					array('empty' => __('No change'), 'value' => $value)
				);?></td>
			<?php endforeach; ?>
		<?php
			$lastIdent = $ident;
		endforeach;

		for ($i = 0; $i <= $lastIdent; $i++) : ?>
			</tr>
		<?php endfor;?>
	</table>

	<?= $this->Form->end(__("Save"));?>

</div>